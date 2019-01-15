module AcmeTls.Interface where

import Options.Applicative
import AcmeTls.Files (getAcmeDirectory)
import Network.ACME.Types (Account(..))
import Control.Applicative

getOptions :: IO Options
getOptions = do
  fp <- getAcmeDirectory
  execParser (opts fp)
  where
    opts p = info (options p <**> helper)
      ( fullDesc
     <> progDesc "Command-line interface for ACME providers."
     <> header "acmetls - interface for ACME providers" )

options :: FilePath -> Parser Options
options fp = Options fp <$> commands

data Options = Options
  { optAcmeDirectory :: FilePath
  , optCommand       :: Command
  }

commands :: Parser Command
commands = subparser $ mconcat
  [ command "account" (info account     (progDesc "Manage your account"))
  , command "orders"  (info submitOrder (progDesc "Manage orders"))
  ]

-- https://tools.ietf.org/html/draft-ietf-acme-acme-15#section-7.1
data Command
  = ViewAccount
  | CreateAccount Bool String
  | SubmitOrder OrderOptions
  -- | FetchChallenges ChallengeOptions
  -- | RespondToChallenges ResponseOptions
  -- | PollForStatus
  -- | FinalizeOrder
  -- | DownloadCertificate


account :: Parser Command
account = viewAccount <|> createAccount

viewAccount :: Parser Command
viewAccount = flag' ViewAccount (long "view" <> help "view account information")

createAccount :: Parser Command
createAccount =
  flag' () (long "create" <> help "Create an account") *> details
  where
    details = CreateAccount
      <$> switch    (long "accept-tos" <> help "Accept the Terms of Service (TOS)")
      <*> strOption (long "email" <> help "Contact for account")

submitOrder :: Parser Command
submitOrder = pure $ SubmitOrder OrderOptions

data OrderOptions = OrderOptions

data ChallengeOptions = ChallengeOptions

data ResponseOptions = ResponseOptions
