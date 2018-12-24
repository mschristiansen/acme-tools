{-# LANGUAGE OverloadedStrings #-}
module Network.ACME.Requests where

import Crypto.JOSE.JWS (JWK)
import Data.Aeson (eitherDecode, encode, decode)
import Data.Aeson.Types (emptyObject)
import Data.ByteString.Char8 (unpack)
import Data.Text.Encoding (decodeUtf8)
import Network.ACME.JWS (AccountUrl(..), signNew, signExisting, signEmpty)
import Network.ACME.Types
import Network.HTTP.Client
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Network.HTTP.Types.Header (RequestHeaders, HeaderName, hContentType, hUserAgent, hAcceptLanguage, hLocation, hAccept)


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

getDirectory :: Manager -> Url -> IO (Either String Directory)
getDirectory http url = do
  putStrLn "Getting directory..."
  request <- parseRequest url
  response <- httpLbs request http
  return $ eitherDecode $ responseBody response

getNonce :: Manager -> String -> IO (Either String Nonce)
getNonce manager url = do
  putStrLn "Getting nonce..."
  initial <- parseRequest url
  let request = initial { method = "HEAD" }
  response <- httpLbs request manager
  let mnonce = fmap (Nonce . unpack) <$> lookup hReplayNonce $ responseHeaders response
  return $ case mnonce of
    Nothing -> Left "getNonce: no nonce in header"
    Just nonce -> Right nonce

createAccount :: Manager -> Url -> JWK -> Nonce -> NewAccount -> IO (Either String (AccountUrl, Nonce))
createAccount manager url key nonce account = do
  putStrLn "Creating account..."
  payload <- signNew key nonce url account
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
          mloc = lookup hLocation hs
          mn   = lookup hReplayNonce hs
      return $
        case (mloc, mn) of
          (Just loc, Just nonce') -> Right (AccountUrl $ decodeUtf8 loc, Nonce $ unpack nonce')
          _                       -> Left "createAccount: something went wrong"

submitOrder :: Manager -> Url -> JWK -> Nonce -> AccountUrl -> NewOrder -> IO (Either String ([AuthUrl], Nonce))
submitOrder manager url key nonce acc order = do
  putStrLn "Submitting Order"
  payload <- signExisting key nonce url acc order
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
          mbody :: Maybe OrderStatus
          mbody = decode $ responseBody response
          auths = maybe [] orAuthorizations mbody
      putStrLn $ "response code: " ++ show (responseStatus response)
      putStrLn $ "order status: " ++ maybe "-" orStatus mbody
      return $
        case mn of
          (Just nonce') -> Right (auths, Nonce $ unpack nonce')
          _             -> Left "submitOrder: something went wrong"

authorize :: Manager -> AuthUrl -> JWK -> Nonce -> AccountUrl -> IO (Either String (Authorization, Nonce))
authorize manager (AuthUrl url) key nonce acc = do
  putStrLn "Authorizing..."
  payload <- signEmpty key nonce url acc
  case payload of
    Left e -> return $ Left $ show e
    Right spayload -> do
      initial <- parseRequest url
      let request = initial { method = "POST"
                            , requestBody = RequestBodyLBS $ encode spayload
                            , requestHeaders = (hAccept, "application/pkix-cert"):acmeHeaders
                            }
      response <- httpLbs request manager
      let hs = responseHeaders response
          mn = lookup hReplayNonce hs
          mauth :: Maybe Authorization
          mauth = decode $ responseBody response
      return $
        case (mauth, mn) of
          (Just auth, Just nonce') -> Right (auth, Nonce $ unpack nonce')
          _                        -> Left "authorize: something went wrong"

proveControl :: Manager -> ChallengeUrl -> JWK -> Nonce -> AccountUrl -> IO (Either String ())
proveControl manager (ChallengeUrl url) key nonce acc = do
  putStrLn "Proving control..."
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
      print response
      return $ Right ()

acmeChallengeUrl :: String
acmeChallengeUrl = "/.well-known/acme-challenge/"
