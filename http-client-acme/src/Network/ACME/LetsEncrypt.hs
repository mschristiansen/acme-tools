module Network.ACME.LetsEncrypt where

import qualified Network.ACME.Requests as A
import Network.ACME.Types
import Network.ACME.JWS (generatePrivateKey)

directoryUrl :: DirectoryUrl
directoryUrl =
  DirectoryUrl "https://acme-staging-v02.api.letsencrypt.org/directory"

getCertificate :: IO ()
getCertificate = do
  http <- A.newTlsManager
  dirs <- A.getDirectory http directoryUrl
  nonce <- A.getNonce http (newNonce dirs)
  let account = Account ["mailto:admin@example1.com"] True
  key <- generatePrivateKey
  (acc, _, n) <- A.createAccount http (newAccount dirs) key nonce account

  let order = NewOrder [OrderIdentifier "example1.com"] Nothing Nothing
  (oid, order', m) <- A.submitOrder http (newOrder dirs) key acc n order
  putStrLn $ "Order Id; " ++ show oid
  (auth, o) <- A.fetchChallenges http (head $ orAuthorizations order') key acc m
  print $ aChallenges auth
  Right (chal, p) <- A.respondToChallenges http (curl $ head $ aChallenges auth) key o acc
  print chal
  A.printHttpChallenge key (token chal)
  return ()
