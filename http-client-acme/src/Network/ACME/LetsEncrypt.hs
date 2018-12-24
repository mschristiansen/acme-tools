module Network.ACME.LetsEncrypt where

import qualified Network.ACME.Requests as A
import Network.ACME.Types
import Network.ACME.JWS (generatePrivateKey)

directoryUrl :: Url
directoryUrl = "https://acme-staging-v02.api.letsencrypt.org/directory"

getCertificate :: IO ()
getCertificate = do
  http <- A.newTlsManager
  Right dirs <- A.getDirectory http directoryUrl
  Right nonce <- A.getNonce http (newNonce dirs)

  let account = NewAccount ["mailto:admin@example1.com"] True
  key <- generatePrivateKey
  Right (acc, n) <- A.createAccount http (newAccount dirs) key nonce account

  let order = NewOrder [OrderIdentifier "example1.com"] Nothing Nothing
  Right (auths, m) <- A.submitOrder http (newOrder dirs) key n acc order
  Right (auth, o) <- A.authorize http (head auths) key m acc
  print $ aChallenges auth
  _ <- A.proveControl http (curl $ head $ aChallenges auth) key o acc
  return ()
