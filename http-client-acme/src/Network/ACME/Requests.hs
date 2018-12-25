{-# LANGUAGE OverloadedStrings #-}
module Network.ACME.Requests where

import Control.Monad (when)
import Control.Exception (throwIO, Exception)
import Crypto.JOSE.JWS (JWK)
import Data.Aeson (eitherDecode, encode, decode)
import Data.Aeson.Types (emptyObject)
import Data.ByteString.Char8 (unpack)
import Data.Text.Encoding (decodeUtf8)
import Network.ACME.JWS (signNew, signExisting, signEmpty, viewThumbprint)
import Network.ACME.Types
import Network.HTTP.Client
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Network.HTTP.Types (status200, status201, status204)
import Network.HTTP.Types.Header (RequestHeaders, HeaderName, hContentType, hUserAgent, hAcceptLanguage, hLocation, hAccept)
import qualified Data.Text as T (unpack, pack)


hReplayNonce :: HeaderName
hReplayNonce = "Replay-Nonce"

newTlsManager :: IO Manager
newTlsManager = newManager tlsManagerSettings


-- Ref. https://tools.ietf.org/html/draft-ietf-acme-acme-14#section-6.1
acmeHeaders :: RequestHeaders
acmeHeaders =
  [ (hContentType, "application/jose+json")
  , (hUserAgent, "http-client-acme")
  , (hAcceptLanguage, "en")
  ]

getDirectory :: Manager -> DirectoryUrl -> IO Directory
getDirectory http (DirectoryUrl url) = do
  req <- parseRequest url
  resp <- httpLbs req http
  let status = responseStatus resp
  if status /= status200
    then throwIO $ AcmeException $ "getDirectory response: " ++ show status
    else case eitherDecode (responseBody resp) of
           Left err -> throwIO $ AcmeException err
           Right dirs -> return dirs

getNonce :: Manager -> NonceUrl -> IO Nonce
getNonce manager (NonceUrl url) = do
  initial <- parseRequest url
  let req = initial { method = "HEAD" }
  resp <- httpLbs req manager
  let mnonce = fmap (Nonce . unpack) <$> lookup hReplayNonce $ responseHeaders resp
      status = responseStatus resp
  -- Specifications says response code should be 200, but
  -- implementation gives 204.
  --
  -- See table in section
  -- https://tools.ietf.org/html/draft-ietf-acme-acme-18#section-7.1
  if status /= status204
    then throwIO $ AcmeException $ "getNonce response: " ++ show status
    else case mnonce of
           Nothing -> throwIO $ AcmeException "getNonce: no nonce in header"
           Just nonce -> return nonce

createAccount :: Manager -> JWK -> Nonce -> AccountUrl -> Account -> IO (AccountId, AccountStatus, Nonce)
createAccount manager key nonce (AccountUrl url) account = do
  payload <- signNew key nonce url account
  case payload of
    Left e -> throwIO $ AcmeException $ "createAccount payload error: " ++ show e
    Right spayload -> do
      initial <- parseRequest url
      let req = initial { method = "POST"
                        , requestBody = RequestBodyLBS $ encode spayload
                        , requestHeaders = acmeHeaders
                        }
      resp <- httpLbs req manager
      let hs = responseHeaders resp
          mloc = lookup hLocation hs
          mn = lookup hReplayNonce hs
          status = responseStatus resp
          macc :: Maybe AccountStatus
          macc = decode $ responseBody resp
      -- 200 returned for an existing account
      -- 201 returned for creating a new account
      if status == status200 || status == status201
        then case (mloc, macc, mn) of
               (Just loc, Just acc, Just nonce') -> return (AccountId $ unpack loc, acc, Nonce $ unpack nonce')
               _                       -> throwIO $ AcmeException "createAccount: account url, account, or nonce not valid"
        else throwIO $ AcmeException $ "createAccount response: " ++ show status

submitOrder :: Manager -> JWK -> AccountId -> Nonce -> OrderUrl -> NewOrder -> IO (OrderId, OrderStatus, Nonce)
submitOrder manager key acc nonce (OrderUrl url) order = do
  payload <- signExisting key nonce url acc order
  case payload of
    Left e -> throwIO $ AcmeException $ "submitOrder error: " ++ show e
    Right spayload -> do
      initial <- parseRequest url
      let req = initial { method = "POST"
                        , requestBody = RequestBodyLBS $ encode spayload
                        , requestHeaders = acmeHeaders
                        }
      resp <- httpLbs req manager
      let hs = responseHeaders resp
          mloc = lookup hLocation hs
          mn = lookup hReplayNonce hs
          morder :: Maybe OrderStatus
          morder = decode $ responseBody resp
          status = responseStatus resp
      if status /= status201
        then throwIO $ AcmeException ""
        else case (mloc, morder, mn) of
               (Just loc, Just order, Just nonce') -> return (OrderId $ unpack loc, order, Nonce $ unpack nonce')
               _             -> throwIO $ AcmeException "submitOrder: no OrderStatus or nonce"

fetchChallenges :: Manager -> JWK -> AccountId -> Nonce -> AuthUrl -> IO (Authorization, Nonce)
fetchChallenges manager key acc nonce (AuthUrl url) = do
  payload <- signEmpty key nonce url acc
  case payload of
    Left e -> throwIO $ AcmeException $ "fetchChallenges: " ++ show e
    Right spayload -> do
      initial <- parseRequest url
      let req = initial { method = "POST"
                        , requestBody = RequestBodyLBS $ encode spayload
                        , requestHeaders = (hAccept, "application/pkix-cert"):acmeHeaders
                        }
      resp <- httpLbs req manager
      let hs = responseHeaders resp
          mn = lookup hReplayNonce hs
          mauth :: Maybe Authorization
          mauth = decode $ responseBody resp
          status = responseStatus resp
      if status /= status200
        then throwIO $ AcmeException $ "fetchChallenges response" ++ show status
        else case (mauth, mn) of
          (Just auth, Just nonce') -> return (auth, Nonce $ unpack nonce')
          _                        -> throwIO $ AcmeException "fetchChallenges: no auth or nonce"

respondToChallenges :: Manager -> JWK -> AccountId -> Nonce -> ChallengeUrl -> IO (Either String (Challenge, Nonce))
respondToChallenges manager key acc nonce (ChallengeUrl url) = do
  payload <- signExisting key nonce url acc emptyObject
  case payload of
    Left e -> return $ Left $ show e
    Right spayload -> do
      initial <- parseRequest url
      let request = initial { method = "POST"
                            , requestBody = RequestBodyLBS $ encode spayload
                            , requestHeaders = acmeHeaders
                            }
      response <- httpLbs request manager
      let hs = responseHeaders response
          mn = lookup hReplayNonce hs
          mc :: Maybe Challenge
          mc = decode $ responseBody response
      return $
        case (mc, mn) of
          (Just c, Just nonce') -> Right (c, Nonce $ unpack nonce')
          _                     -> Left "proveControl: error"


pollForStatus :: IO ()
pollForStatus = undefined

finalizeOrder :: IO ()
finalizeOrder = undefined

downloadCertificate :: IO ()
downloadCertificate = undefined


data AcmeException
  = AcmeException String
  | AccountDoesNotExist
  deriving Show

instance Exception AcmeException

-- https://tools.ietf.org/html/draft-ietf-acme-acme-15#section-8.1
keyAuthorization :: JWK -> Token -> String
keyAuthorization key (Token t) = t ++ "." ++ viewThumbprint key

-- https://tools.ietf.org/html/draft-ietf-acme-acme-15#section-8.3
createChallengeHttpUrl :: OrderIdentifier -> Token -> Url
createChallengeHttpUrl (OrderIdentifier domain) (Token t) =
  "http://" ++ domain ++ "/.well-known/acme-challenge/" ++ t

-- https://tools.ietf.org/html/draft-ietf-acme-acme-15#section-8.3
createChallengeHttpBody :: JWK -> Token -> String
createChallengeHttpBody = keyAuthorization

-- https://tools.ietf.org/html/draft-ietf-acme-acme-15#section-8.4
createChallengeDnsRecord :: OrderIdentifier -> JWK -> Token -> String
createChallengeDnsRecord (OrderIdentifier domain) k t =
  "_acme-challenge." ++ domain ++ ". 300 IN TXT \"" ++ keyAuthorization k t ++"\""
