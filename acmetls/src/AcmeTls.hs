{-# LANGUAGE RecordWildCards #-}
module AcmeTls
    ( main
    ) where

import Control.Exception (SomeException, catch)
import Control.Monad (when)
import Data.Maybe (fromMaybe)
import Network.ACME.JWS (JWK, readKey, writeKey, generatePrivateKey)
import Network.ACME.LetsEncrypt (directoryUrl)
import Network.ACME.Requests (newTlsManager, getDirectory, getNonce, createAccount, submitOrder, fetchChallenges, createChallengeDnsRecord, createChallengeHttpUrl, createChallengeHttpBody, respondToChallenges)
import Network.ACME.Types (Account(..), Directory(..), AccountStatus(..), NewOrder(..), OrderIdentifier(..), OrderStatus(..), Nonce, Authorization(..), Challenge(..), isChallengeType)
import AcmeTls.Files (getAcmeDirectory)


main :: IO ()
main = do
  putStrLn "Interactive Mode"
  putStrLn ""
  fp <- getAcmeDirectory
  putStr $ "Checking for existing key in " ++ fp ++ " ... "
  mkey <- catch (readKey fp) (\e -> print (e :: SomeException) >> return Nothing)
  key <- case mkey of
    Nothing -> do
      putStrLn "No key found"
      putStrLn $ "Generating new key and storing in " ++ fp
      k <- generatePrivateKey
      writeKey fp k
      return k
    Just k  -> do
      putStrLn "Found key"
      return k
  putStr "Checking for account with Let's Encrypt ... "
  http <- newTlsManager
  Directory{..} <- getDirectory http directoryUrl
  nonce <- getNonce http newNonce
  (aid, acc, n) <- createAccount http key nonce newAccount (NewAccount ["mailto:mikkel@rheosystems.com"] True)
  putStrLn "Found account"
  putStrLn $ "Account ID : " ++ show aid
  printAccount acc
  putStrLn "Submit new order?"
  yes <- yesOrNo
  when yes $ do
    order <- enterOrder
    (oid, order', n) <- submitOrder http key aid n newOrder order
    putStrLn $ "Order ID : " ++ show oid
    printOrder order'
    putStrLn "Fetching challenges..."
    (auths, m) <- mapMwithNonce (fetchChallenges http key aid) (orAuthorizations order') n
    mapM_ (printAuthorization key) auths
    ct <- selectChallengeType
    (_, o) <- mapMwithNonce (respondToChallenges http key aid)  (map curl $ filter (isChallengeType ct) $ concatMap aChallenges auths) m
    let waitStatus :: Nonce -> IO ()
        waitStatus n = do
          putStrLn "Check status again?"
          yes <- yesOrNo
          if yes
            then do
              (auths, n') <- mapMwithNonce (fetchChallenges http key aid) (orAuthorizations order') n
              mapM_ (printAuthorization key) auths
              waitStatus n'
            else waitStatus n
    waitStatus o
    return ()


yesOrNo :: IO Bool
yesOrNo = do
  putStrLn "y or n"
  c <- getChar
  case c of
    'y' -> return True
    'n' -> return False
    _ -> yesOrNo

enterOrder :: IO NewOrder
enterOrder = (\ds -> NewOrder ds Nothing Nothing) <$> go []
  where
    go ds = do
      putStrLn "Enter domain name e.g. example1.com"
      s <- getLine
      case s of
        "" -> do
          putStrLn "invalid domain name"
          go ds
        d  -> do
          let ds' = OrderIdentifier d:ds
          putStrLn $ "Domains : " ++ show ds'
          putStrLn "More?"
          yes <- yesOrNo
          if yes then go ds' else return ds'

selectChallengeType :: IO String
selectChallengeType = do
  putStrLn "Type 'dns' or 'http' to continue and respond to those challenges"
  s <- getLine
  case s of
    "dns" -> return "dns-01"
    "http" -> return "http-01"
    _ -> selectChallengeType

printAccount :: AccountStatus -> IO ()
printAccount AccountStatus{..} = do
  putStrLn $ "Account status       : " ++ status
  putStrLn $ "Account contacts     : " ++ concat contact
  putStrLn $ "Account orders       : " ++ maybe "(not implemented for let's encrypt)" show orders

printOrder :: OrderStatus -> IO ()
printOrder OrderStatus{..} = do
  putStrLn $ "Order status         : " ++ orStatus
  putStrLn $ "Order expires        : " ++ orExpires
  putStrLn $ "Order Identifiers    : " ++ concatMap show orIdentifiers
  putStrLn $ "Order authorizations : " ++ concatMap show orAuthorizations
  putStrLn $ "Order finalize       : " ++ show orFinalize

printAuthorization :: JWK -> Authorization -> IO ()
printAuthorization key Authorization{..} = do
  putStrLn $ "Authorization for    : " ++ show aIdentifier
  putStrLn $ "Authorization status : " ++ aStatus
  putStrLn $ "Authorization expires: " ++ fromMaybe "-" aExpires
  putStrLn "Complete one of the below challenges for each domain"
  mapM_ (printChallenge key aIdentifier) aChallenges

printChallenge :: JWK -> OrderIdentifier -> Challenge -> IO ()
printChallenge key oid Challenge{..} = do
  putStrLn $ "Challenge type       : " ++ ctype
  putStrLn $ "Challenge status     : " ++ show cstatus
  putStrLn $ "Challenge url        : " ++ show curl
  case ctype of
    "dns-01" -> do
      putStrLn "Add this DNS TXT record   : "
      putStrLn $ "  " ++ createChallengeDnsRecord oid key token
    "http-01" -> do
      putStrLn "On this url:"
      putStrLn $ "  " ++ createChallengeHttpUrl oid token
      putStrLn "And give this response:"
      putStrLn $ "  " ++ createChallengeHttpBody key token
    _ -> putStrLn $ "Unknown challenge: " ++ ctype

mapMwithNonce :: (Nonce -> a -> IO (b, Nonce)) -> [a] -> Nonce -> IO ([b], Nonce)
mapMwithNonce f = go []
  where
    go bs [] n' = return (reverse bs, n')
    go bs (a:as) n' = do
      (b, n'') <- f n' a
      go (b:bs) as n''
