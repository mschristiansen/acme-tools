{-# LANGUAGE OverloadedStrings #-}
module Network.Wai.Middleware.ACME
  ( acmeDefault
  , acme
  , isAcmeChallenge
  ) where

import Network.ACME.LetsEncrypt
import Network.HTTP.Types (hLocation, methodGet, status301, status307, status200)
import Network.Wai


acmeDefault :: Config
acmeDefault = Config { secureRedirect = True }

data Config = Config
  { secureRedirect :: Bool
  }

acme :: Config -> Middleware
acme cfg app req respond
  | isAcmeChallenge req = app req respond


isAcmeChallenge :: Request -> Bool
isAcmeChallenge req =
  case pathInfo req of
    [".well-known", "acme-challenge", _token] -> True
    _  -> False

success :: Response
success = responseBuilder status200 [] mempty
