{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}
module Network.ACME.Types where

import GHC.Generics (Generic)
import Data.Aeson


type Url = String

newtype Nonce = Nonce String deriving Show

newtype AuthUrl = AuthUrl String deriving (Show, FromJSON)

newtype ChallengeUrl = ChallengeUrl String deriving (Show, FromJSON)

data Directory = Directory
  { newNonce   :: Url
  , newAccount :: Url
  , newOrder   :: Url
  , revokeCert :: Url
  , keyChange  :: Url
  , meta       :: DirectoryMeta
  } deriving (Generic, Show)

instance FromJSON Directory where
  parseJSON = genericParseJSON defaultOptions

data DirectoryMeta = DirectoryMeta
  { caaIdentities  :: [String]
  , termsOfService :: Url
  , website        :: Url
  } deriving (Generic, Show)

instance FromJSON DirectoryMeta where
  parseJSON = genericParseJSON defaultOptions

data NewAccount = NewAccount
  { contact              :: [String]
  , termsOfServiceAgreed :: Bool
  } deriving (Generic, Show)

instance ToJSON NewAccount where
  toEncoding = genericToEncoding defaultOptions

data AccountStatus = AccountStatus
  { status :: String
  , orders :: Maybe Url
  } deriving (Generic, Show)

instance FromJSON AccountStatus where
  parseJSON = genericParseJSON defaultOptions

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
  , orFinalize       :: String
  } deriving Show

instance FromJSON OrderStatus where
  parseJSON = withObject "OrderStatus" $ \o ->
    OrderStatus <$> o .: "status"
                <*> o .: "expires"
                <*> o .:? "notBefore"
                <*> o .:? "notAfter"
                <*> o .: "identifiers"
                <*> o .: "authorizations"
                <*> o .: "finalize"

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
  , cstatus :: String
  , curl    :: ChallengeUrl
  , token   :: String
  } deriving Show

instance FromJSON Challenge where
  parseJSON = withObject "Challenge" $ \o ->
    Challenge <$> o .: "type"
              <*> o .: "status"
              <*> o .: "url"
              <*> o .: "token"
