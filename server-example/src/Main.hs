{-# LANGUAGE OverloadedStrings #-}
module Main where

import Network.HTTP.Types (status200)
import Network.Wai (responseLBS)
import Network.Wai.Handler.Warp (defaultSettings, setPort)
import Network.Wai.Handler.WarpTLS (runTLS, tlsSettingsMemory)
import Network.Wai.Middleware.ACME (acme, acmeDefault)


main :: IO ()
main = runTLS tls cfg $ middleware app
  where
    tls = tlsSettingsMemory "a" "a"
    cfg = setPort 8080 defaultSettings
    middleware = acme acmeDefault
    app req respond = respond $ responseLBS status200 [] "Hello World"
