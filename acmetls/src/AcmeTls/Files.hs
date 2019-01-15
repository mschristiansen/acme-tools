module AcmeTls.Files where

import System.Directory
import Data.PEM

getAcmeDirectory :: IO FilePath
getAcmeDirectory = getXdgDirectory XdgConfig "acmetls"
