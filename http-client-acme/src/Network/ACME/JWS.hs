{-# LANGUAGE OverloadedStrings #-}
module Network.ACME.JWS
  ( AccountUrl(..)
  , generatePrivateKey
  , viewPublicKey
  , viewThumbprint
  , signNew
  , signExisting
  , signEmpty
  , enc64url
  , dec64url
  ) where

import Control.Lens (Lens', (&), set, view, review, preview, re)
import Control.Monad.Trans.Except (runExceptT)
import Crypto.JOSE.JWK (JWK, base64url)
import Crypto.JOSE.JWS hiding (header)
import Data.Aeson (ToJSON, encode, (.=))
import Data.Functor.Identity
import Data.Text (Text)
import Network.ACME.Types (Nonce(..))
import qualified Data.ByteString.Lazy as L
import Data.ByteString.Char8

newtype AccountUrl = AccountUrl Text


-- | Generate a 4096 bit JSON Web Key (JWK).
generatePrivateKey :: IO JWK
generatePrivateKey = genJWK (ECGenParam P_256)

viewPublicKey :: JWK -> Maybe JWK
viewPublicKey = view asPublicKey

viewThumbprint :: JWK -> String
viewThumbprint jwk = unpack $ view (re (base64url . digest)) d
  where
    d :: Digest SHA256
    d = view thumbprint jwk

signNew :: ToJSON a => JWK -> Nonce -> String -> a -> IO (Either Error (JWS Identity Protection ACMEHeader))
signNew k (Nonce n) url payload = runExceptT $ signJWS (encode payload) (Identity (header, k))
  where
    -- Can be signed with either ES256 or EdDSA
    -- Each ES256 with RSA key
    header :: ACMEHeader Protection
    header = ACMEHeader (newJWSHeader (Protected, ES256)
      & set jwk (HeaderParam Protected <$> viewPublicKey k)) n url

signExisting :: ToJSON a => JWK -> Nonce -> String -> AccountUrl -> a -> IO (Either Error (JWS Identity Protection ACMEHeader))
signExisting k (Nonce n) url (AccountUrl acc) payload = runExceptT $ signJWS (encode payload) (Identity (header, k))
  where
    header :: ACMEHeader Protection
    header = ACMEHeader (newJWSHeader (Protected, ES256)
      & set kid (Just $ HeaderParam Protected acc)) n url

-- | Used for POST-as-GET requests to sign an empty payload
-- https://tools.ietf.org/html/draft-ietf-acme-acme-15#section-6.3
signEmpty :: JWK -> Nonce -> String -> AccountUrl -> IO (Either Error (JWS Identity Protection ACMEHeader))
signEmpty k (Nonce n) url (AccountUrl acc) = runExceptT $ signJWS [] (Identity (header, k))
  where
    header :: ACMEHeader Protection
    header = ACMEHeader (newJWSHeader (Protected, ES256)
      & set kid (Just $ HeaderParam Protected acc)) n url

-- | Base64Url Encode
enc64url :: L.ByteString -> L.ByteString
enc64url = review base64url

-- | Base64Url decode
dec64url :: L.ByteString -> Maybe L.ByteString
dec64url = preview base64url

data ACMEHeader p = ACMEHeader
  { _acmeJwsHeader :: JWSHeader p
  , _acmeNonce     :: String
  , _acmeUrl       :: String
  }

acmeJwsHeader :: Lens' (ACMEHeader p) (JWSHeader p)
acmeJwsHeader f s@(ACMEHeader { _acmeJwsHeader = a}) =
  fmap (\a' -> s { _acmeJwsHeader = a'}) (f a)

acmeNonce :: Lens' (ACMEHeader p) String
acmeNonce f s@(ACMEHeader { _acmeNonce = a}) =
  fmap (\a' -> s { _acmeNonce = a'}) (f a)

acmeUrl :: Lens' (ACMEHeader p) String
acmeUrl f  s@(ACMEHeader { _acmeUrl = a}) =
  fmap (\a' -> s { _acmeUrl = a'}) (f a)

instance HasJWSHeader ACMEHeader where
  jwsHeader = acmeJwsHeader

instance HasParams ACMEHeader where
  parseParamsFor proxy hp hu =
    ACMEHeader <$> parseParamsFor proxy hp hu
               <*> headerRequiredProtected "nonce" hp hu
               <*> headerRequiredProtected "url" hp hu
  params h =
    (True, "url" .= view acmeUrl h) :
    (True, "nonce" .= view acmeNonce h) : params (view acmeJwsHeader h)
  extensions = const ["nonce", "url"]
