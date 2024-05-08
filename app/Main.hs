{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Control.Monad (forever)
import Network.UDP qualified as UDP

main :: IO ()
main = do
    sock <- UDP.serverSocket ("127.0.0.1", 2053)
    putStrLn "Server started"
    forever $ do
        (r, clientSock) <- UDP.recvFrom sock
        print r
        UDP.sendTo sock "" clientSock