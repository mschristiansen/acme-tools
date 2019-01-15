{-# LANGUAGE OverloadedStrings #-}
module Network.ACME.Requests where

import Control.Exception (throwIO, Exception)
import Crypto.JOSE.JWS (JWK)
import Data.Aeson (eitherDecode, encode, decode)
import Data.Aeson.Types (emptyObject)
import Data.ByteString.Char8 (unpack)
import Network.ACME.JWS (Signed, signNew, signExisting, signEmpty, viewThumbprint, sha256Digest)
import Network.ACME.Types
import Network.HTTP.Client
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Network.HTTP.Types (status200, status201, status204)
import Network.HTTP.Types.Header (RequestHeaders, hContentType, hUserAgent, hAcceptLanguage, hLocation, hAccept)


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
  let st = responseStatus resp
  if st == status200
    then case eitherDecode $ responseBody resp of
      Left err -> throwIO $ AcmeException err
      Right dirs -> return dirs
    else throwIO $ AcmeException $ "getDirectory response: " ++ show st

getNonce :: Manager -> NonceUrl -> IO Nonce
getNonce manager (NonceUrl url) = do
  initial <- parseRequest url
  let req = initial { method = "HEAD" }
  resp <- httpLbs req manager
  let st = responseStatus resp
  -- Specifications says response code should be 200, but
  -- implementation gives 204. Should be fixed in new release.
  --
  -- See table in section
  -- https://tools.ietf.org/html/draft-ietf-acme-acme-18#section-7.1
  if st == status200 || st == status204
    then case lookupNonce resp of
           Nothing -> throwIO $ AcmeException "getNonce: no nonce in header"
           Just nonce -> return nonce
    else throwIO $ AcmeException $ "getNonce response: " ++ show st

createAccount :: Manager -> JWK -> Nonce -> AccountUrl -> Account -> IO (AccountId, AccountStatus, Nonce)
createAccount manager key nonce (AccountUrl url) account = do
  payload <- signNew key nonce url account
  case payload of
    Left e -> throwIO $ AcmeException $ "createAccount payload error: " ++ show e
    Right spayload -> do
      initial <- parseRequest url
      resp <- httpLbs (includePayload spayload initial) manager
      let mloc = lookup hLocation (responseHeaders resp)
          st = responseStatus resp
          macc :: Maybe AccountStatus
          macc = decode $ responseBody resp
      -- 200 returned for an existing account
      -- 201 returned for creating a new account
      if st == status200 || st == status201
        then case (mloc, macc, lookupNonce resp) of
               (Just loc, Just acc, Just nonce') -> return (AccountId $ unpack loc, acc, nonce')
               _                                 -> throwIO $ AcmeException "createAccount: account url, account, or nonce not valid"
        else throwIO $ AcmeException $ "createAccount response: " ++ show st

submitOrder :: Manager -> JWK -> AccountId -> Nonce -> OrderUrl -> NewOrder -> IO (OrderId, OrderStatus, Nonce)
submitOrder manager key acc nonce (OrderUrl url) order = do
  payload <- signExisting key nonce url acc order
  case payload of
    Left e -> throwIO $ AcmeException $ "submitOrder error: " ++ show e
    Right spayload -> do
      initial <- parseRequest url
      resp <- httpLbs (includePayload spayload initial) manager
      let hs = responseHeaders resp
          mloc = lookup hLocation hs
          morder :: Maybe OrderStatus
          morder = decode $ responseBody resp
          st = responseStatus resp
      if st /= status201
        then throwIO $ AcmeException $ "submitOrder response: " ++ show st
        else case (mloc, morder, lookupNonce resp) of
               (Just loc, Just o, Just nonce') -> return (OrderId $ unpack loc, o, nonce')
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
      let mauth :: Maybe Authorization
          mauth = decode $ responseBody resp
          st = responseStatus resp
      if st /= status200
        then throwIO $ AcmeException $ "fetchChallenges response:" ++ show st
        else case (mauth, lookupNonce resp) of
          (Just auth, Just nonce') -> return (auth, nonce')
          _                        -> throwIO $ AcmeException "fetchChallenges: no auth or nonce"

respondToChallenges :: Manager -> JWK -> AccountId -> Nonce -> ChallengeUrl -> IO (Challenge, Nonce)
respondToChallenges manager key acc nonce (ChallengeUrl url) = do
  payload <- signExisting key nonce url acc emptyObject
  case payload of
    Left e -> throwIO $ AcmeException $ "respondToChallenges: " ++ show e
    Right spayload -> do
      initial <- parseRequest url
      let req = initial { method = "POST"
                        , requestBody = RequestBodyLBS $ encode spayload
                        , requestHeaders = acmeHeaders
                        }
      resp <- httpLbs req manager
      let mc :: Maybe Challenge
          mc = decode $ responseBody resp
          st = responseStatus resp
      if st /= status200
      then throwIO $ AcmeException $ "respondToChallenges response:" ++ show st
      else case (mc, lookupNonce resp) of
          (Just c, Just nonce') -> return (c, nonce')
          _                     -> throwIO $ AcmeException "respondToChallenges: no challenge or nonce"

pollForStatus :: IO ()
pollForStatus = undefined

finalizeOrder :: IO ()
finalizeOrder = undefined

downloadCertificate :: IO ()
downloadCertificate = undefined

lookupNonce :: Response a -> Maybe Nonce
lookupNonce resp =
  fmap (Nonce . unpack) <$> lookup "Replay-Nonce" $ responseHeaders resp

includePayload :: Signed -> Request -> Request
includePayload spayload initial =
  initial { method = "POST"
          , requestBody = RequestBodyLBS $ encode spayload
          , requestHeaders = acmeHeaders
          }


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
  "_acme-challenge." ++ domain ++ ". 300 IN TXT \"" ++ sha256Digest (keyAuthorization k t) ++"\""
