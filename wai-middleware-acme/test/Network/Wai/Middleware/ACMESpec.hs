{-# LANGUAGE OverloadedStrings #-}
module Network.Wai.Middleware.ACMESpec where

import Network.Wai (defaultRequest, pathInfo)
import Network.Wai.Middleware.ACME (isAcmeChallenge)
import Test.Hspec (Spec, describe, it, shouldBe)

spec :: Spec
spec = do
  describe "isAcmeChallenge" $ do
    it "reject a default request" $
      isAcmeChallenge defaultRequest `shouldBe` False
    it "accept a acme request" $
      let req = defaultRequest { pathInfo = [".well-known", "acme-challenge", "abc"]} in
      isAcmeChallenge req `shouldBe` True
