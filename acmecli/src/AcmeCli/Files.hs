module AcmeCli.Files where

import System.Directory


getAcmeDirectory :: IO FilePath
getAcmeDirectory = getXdgDirectory XdgConfig "acmecli"
