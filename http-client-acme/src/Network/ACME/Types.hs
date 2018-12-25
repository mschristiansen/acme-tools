{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}
module Network.ACME.Types where

import GHC.Generics (Generic)
import Data.Aeson
import Data.Text (Text)

type Url = String
type Email = String

newtype Nonce = Nonce String deriving Show

newtype DirectoryUrl = DirectoryUrl Url deriving (Show, FromJSON)

newtype NonceUrl = NonceUrl Url deriving (Show, FromJSON)

newtype AccountUrl = AccountUrl Url deriving (Show, FromJSON)

newtype AccountId = AccountId Url deriving (Show, FromJSON)

newtype OrderUrl = OrderUrl Url deriving (Show, FromJSON)

newtype OrderId = OrderId Url deriving (Show, FromJSON)

newtype AuthUrl = AuthUrl Url deriving (Show, FromJSON)

newtype ChallengeUrl = ChallengeUrl Url deriving (Show, FromJSON)

newtype FinalizeUrl = FinalizeUrl Url deriving (Show, FromJSON)

newtype CertificateUrl = CertificateUrl Url deriving (Show, FromJSON)

data Directory = Directory
  { newNonce   :: NonceUrl
  , newAccount :: AccountUrl
  , newOrder   :: OrderUrl
  , newAuthz   :: Maybe Url
  , revokeCert :: Url
  , keyChange  :: Url
  , meta       :: Maybe DirectoryMeta
  } deriving Show

instance FromJSON Directory where
  parseJSON = withObject "Directory" $ \o ->
    Directory <$> o .:  "newNonce"
              <*> o .:  "newAccount"
              <*> o .:  "newOrder"
              <*> o .:? "newAutz"
              <*> o .:  "revokeCert"
              <*> o .:  "keyChange"
              <*> o .:? "meta"

data DirectoryMeta = DirectoryMeta
  { caaIdentities  :: Maybe [String]
  , termsOfService :: Maybe Url
  , website        :: Maybe Url
  } deriving Show

instance FromJSON DirectoryMeta where
  parseJSON = withObject "DirectoryMeta" $ \o ->
    DirectoryMeta <$> o .:? "caaIdentities"
                  <*> o .:? "termsOfService"
                  <*> o .:? "website"

-- contact must be one or more email addresses prepended with
-- "mailto:" e.g. "mailto:admin@example1.com". Terms of service (TOS)
-- must require some user interaction according to ACME
-- specifications.
data Account
  = Account
    { accountContact   :: [Email]
    , accountTosAgreed :: Bool
    }
  | ExistingAccount
  deriving Show

instance ToJSON Account where
  toJSON acc =
    case acc of
      Account{..} ->
        object [ "contact"              .= accountContact
               , "termsOfServiceAgreed" .= accountTosAgreed
               ]
      ExistingAccount ->
        object [ "onlyReturnExisting" .= True ]
  toEncoding acc =
    case acc of
      Account{..} ->
        pairs $ mconcat [ "contact"              .= accountContact
                        , "termsOfServiceAgreed" .= accountTosAgreed
                        ]
      ExistingAccount ->
        pairs ("onlyReturnExisting" .= True)

-- Let's Encrypt currently haven't implemented the orders field as per
-- this issue: https://github.com/letsencrypt/boulder/issues/3335
data AccountStatus = AccountStatus
  { status  :: String
  , contact :: [Email]
  , orders  :: Maybe OrderId
  } deriving Show

instance FromJSON AccountStatus where
  parseJSON = withObject "AccountStatus" $ \o ->
    AccountStatus <$> o .:  "status"
                  <*> o .:  "contact"
                  <*> o .:? "orders"

data NewOrder = NewOrder
  { identifiers :: [OrderIdentifier]
  , notBefore   :: Maybe String
  , notAfter    :: Maybe String
  } deriving (Generic, Show)

instance ToJSON NewOrder where
  toEncoding = genericToEncoding defaultOptions


newtype OrderIdentifier = OrderIdentifier String deriving Show

-- There is currently only the option for DNS identification
instance ToJSON OrderIdentifier where
  toJSON (OrderIdentifier v) =
    object ["type" .= ("dns" :: String), "value" .= v]
  toEncoding (OrderIdentifier v) =
    pairs ("type" .= ("dns" :: String) <> "value" .= v)

instance FromJSON OrderIdentifier where
  parseJSON = withObject "OrderIdentifier" $ \o ->
    OrderIdentifier <$> o .: "value"

data OrderStatus = OrderStatus
  { orStatus         :: String
  , orExpires        :: String
  , orNotBefore      :: Maybe String
  , orNotAfter       :: Maybe String
  , orIdentifiers    :: [OrderIdentifier]
  , orAuthorizations :: [AuthUrl]
  , orFinalize       :: FinalizeUrl
  , orCertificate    :: Maybe CertificateUrl
  } deriving Show

instance FromJSON OrderStatus where
  parseJSON = withObject "OrderStatus" $ \o ->
    OrderStatus <$> o .:  "status"
                <*> o .:  "expires"
                <*> o .:? "notBefore"
                <*> o .:? "notAfter"
                <*> o .:  "identifiers"
                <*> o .:  "authorizations"
                <*> o .:  "finalize"
                <*> o .:? "certificate"

data Authorization = Authorization
  { aIdentifier :: OrderIdentifier
  , aStatus     :: String
  , aExpires    :: Maybe String
  , aChallenges :: [Challenge]
  , aWildcard   :: Maybe Bool
  } deriving Show

instance FromJSON Authorization where
  parseJSON = withObject "Authorization" $ \o ->
    Authorization <$> o .:  "identifier"
                  <*> o .:  "status"
                  <*> o .:? "expires"
                  <*> o .:  "challenges"
                  <*> o .:? "wildcard"

data Challenge = Challenge
  { ctype   :: String
  , cstatus :: ChallengeStatus
  , curl    :: ChallengeUrl
  , token   :: String
  } deriving Show

instance FromJSON Challenge where
  parseJSON = withObject "Challenge" $ \o ->
    Challenge <$> o .: "type"
              <*> o .: "status"
              <*> o .: "url"
              <*> o .: "token"

data ChallengeStatus
  = ChallengePending
  | ChallengeProcessing
  | ChallengeValid
  | ChallengeInvalid
  deriving Show

instance FromJSON ChallengeStatus where
  parseJSON = withText "ChallengeStatus" $ \s ->
    case s of
      "pending"    -> pure ChallengePending
      "processing" -> pure ChallengeProcessing
      "valid"      -> pure ChallengeValid
      "invalid"    -> pure ChallengeInvalid
      _            -> fail "Challenge status not recognised"

data AcmeServerError = AcmeServerError
  { errorType   :: String
  , errorDetail :: String
  }

instance FromJSON AcmeServerError where
  parseJSON = withObject "AcmeServerError" $ \o ->
    AcmeServerError <$> o .: "type"
                    <*> o .: "detail"
