{-# LANGUAGE RecordWildCards #-}
module AcmeCli
    ( main
    ) where

import Control.Exception (SomeException, catch)
import Control.Monad (when)
import Data.Maybe (fromMaybe)
import Network.ACME.JWS (readKey, writeKey, generatePrivateKey)
import Network.ACME.LetsEncrypt (directoryUrl)
import Network.ACME.Requests (newTlsManager, getDirectory, getNonce, createAccount, submitOrder, fetchChallenges)
import Network.ACME.Types (Account(..), Directory(..), AccountStatus(..), NewOrder(..), OrderIdentifier(..), OrderStatus(..), Nonce, Authorization(..), Challenge(..))


keyLocation :: String
keyLocation = "acmekey.json"

main :: IO ()
main = do
  putStrLn "Interactive Mode"
  putStrLn ""
  putStr $ "Checking for existing key in " ++ keyLocation ++ " ... "
  mkey <- catch (readKey keyLocation) (\e -> print (e :: SomeException) >> return Nothing)
  key <- case mkey of
    Nothing -> do
      putStrLn $ "No key found"
      putStrLn $ "Generating new key and storing in " ++ keyLocation
      k <- generatePrivateKey
      writeKey keyLocation k
      return k
    Just k  -> do
      putStrLn "Found key"
      return k
  putStr "Checking for account with Let's Encrypt ... "
  http <- newTlsManager
  Directory{..} <- getDirectory http directoryUrl
  nonce <- getNonce http newNonce
  (aid, acc, n) <- createAccount http key nonce newAccount ExistingAccount
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
    (auths, _) <- mapMwithNonce (fetchChallenges http key aid) (orAuthorizations order') n
    mapM_ printAuthorization auths
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

printAccount :: AccountStatus -> IO ()
printAccount AccountStatus{..} = do
  putStrLn $ "Account status       : " ++ status
  putStrLn $ "Account contacts     : " ++ concat contact
  putStrLn $ "Account orders       : " ++ maybe "(not implemented for let's encrypt)" show orders

printOrder :: OrderStatus -> IO ()
printOrder OrderStatus{..} = do
  putStrLn $ "Order status         : " ++ orStatus
  putStrLn $ "Order expires        : " ++ orExpires
  putStrLn $ "Order Identifiers    : " ++ concat (map show orIdentifiers)
  putStrLn $ "Order authorizations : " ++ concat (map show orAuthorizations)
  putStrLn $ "Order finalize       : " ++ show orFinalize

printAuthorization :: Authorization -> IO ()
printAuthorization Authorization{..} = do
  putStrLn $ "Authorization for    : " ++ show aIdentifier
  putStrLn $ "Authorization status : " ++ aStatus
  putStrLn $ "Authorization expires: " ++ fromMaybe "-" aExpires
  mapM_ printChallenge aChallenges

printChallenge :: Challenge -> IO ()
printChallenge Challenge{..} = do
  putStrLn $ "Challenge type       : " ++ ctype
  putStrLn $ "Challenge status     : " ++ show cstatus

mapMwithNonce :: (Nonce -> a -> IO (b, Nonce)) -> [a] -> Nonce -> IO ([b], Nonce)
mapMwithNonce f xs n = go [] xs n
  where
    go bs [] n' = return (reverse bs, n')
    go bs (a:as) n' = do
      (b, n'') <- f n' a
      go (b:bs) as n''
