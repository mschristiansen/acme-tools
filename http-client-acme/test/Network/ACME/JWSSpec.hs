{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.ACME.JWSSpec where

import Test.Hspec
import GHC.Generics
import Network.ACME.JWS
import Network.ACME.LetsEncrypt
import Data.Either (isRight)
import Data.Aeson (FromJSON, encode, decode)
import Network.ACME.Types (Nonce(..), NewAccount(..))
import Data.String (fromString)

account :: NewAccount
account = NewAccount ["admin@example1.com"] True

spec :: Spec
spec = do
  describe "sign" $ do
    it "correct signs an account payload" $ do
      k <- generatePrivateKey
      payload <- signNew k (Nonce "12345") "https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce" account
      let Right foo = encode <$> payload
      isRight payload `shouldBe` True
