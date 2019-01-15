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
  let account = NewAccount ["mailto:admin@example1.com"] True
  key <- generatePrivateKey
  (acc, _, n) <- A.createAccount http key nonce (newAccount dirs) account

  let order = NewOrder [OrderIdentifier "example1.com"] Nothing Nothing
  (oid, order', m) <- A.submitOrder http key acc n (newOrder dirs) order
  putStrLn $ "Order Id; " ++ show oid
  (auth, o) <- A.fetchChallenges http key acc m (head $ orAuthorizations order')
  print $ aChallenges auth
  (chal, p) <- A.respondToChallenges http key acc o (curl $ head $ aChallenges auth)
  print chal
  return ()
