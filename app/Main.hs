{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Data.Text.Encoding (decodeLatin1)
import Data.Binary (Word16, Word8, Word32)
import Data.Binary.Get qualified as BG
import Data.Binary.Put qualified as BP
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as BSL
import Control.Monad (forever)
import Network.UDP qualified as UDP
import Data.Bits (testBit, Bits (shiftR, (.&.)))
import Data.ByteString (ByteString)
import Data.Text (Text)
import Data.Text qualified as T

data DNSHeader = DNSHeader
    { _id :: Word16
    , _qr :: Bool
    , _opcode :: Word8
    , _aa :: Bool
    , _tc :: Bool
    , _rd :: Bool
    , _ra :: Bool
    , _z :: Word8
    , _rcode :: Word8
    , _qdcount :: Word16
    , _ancount :: Word16
    , _nscount :: Word16
    , _arcount :: Word16
    }
    deriving Show

data DNSQuestion = DNSQuestion
    { _qname :: Text
    , _qtype :: Word16
    , _qclass :: Word16
    }
    deriving Show

data DNSResourceRecord = DNSResourceRecord
    { _name :: Text
    , _rtype :: Word16
    , _rclass :: Word16
    , _ttl :: Word32
    , _rdlength :: Word16
    , _rdata :: Text
    }
    deriving Show

data DNSMessage = DNSMessage
    { _header :: DNSHeader
    , _question :: DNSQuestion
    , _answer :: [DNSResourceRecord]
    , _authority :: [DNSResourceRecord]
    , _additional :: [DNSResourceRecord]
    }
    deriving Show

dnsMessageParser :: BG.Get DNSMessage
dnsMessageParser = do
    header <- dnsHeaderParser
    question <- dnsQuestionParser
    answer <- many dnsResourceRecordParser
    authority <- many dnsResourceRecordParser
    additional <- many dnsResourceRecordParser
    return $ DNSMessage header question answer authority additional
    where
        dnsHeaderParser :: BG.Get DNSHeader
        dnsHeaderParser = do
            id <- BG.getWord16be
            flags <- BG.getWord16be
            qdcount <- BG.getWord16be
            ancount <- BG.getWord16be
            nscount <- BG.getWord16be
            arcount <- BG.getWord16be
            return $ DNSHeader
                { _id = id
                , _qr = testBit flags 15
                , _opcode = fromIntegral $ flags `shiftR` 11 .&. 0xF
                , _aa = testBit flags 10
                , _tc = testBit flags 9
                , _rd = testBit flags 8
                , _ra = testBit flags 7
                , _z = fromIntegral $ flags `shiftR` 4 .&. 0x7
                , _rcode = fromIntegral $ flags .&. 0xF
                , _qdcount = qdcount
                , _ancount = ancount
                , _nscount = nscount
                , _arcount = arcount
                }

        dnsQuestionParser :: BG.Get DNSQuestion
        dnsQuestionParser = do
            qname <- dnsNameParser
            qtype <- BG.getWord16be
            DNSQuestion qname qtype <$> BG.getWord16be

        dnsResourceRecordParser :: BG.Get DNSResourceRecord
        dnsResourceRecordParser = do
            name <- dnsNameParser
            rtype <- BG.getWord16be
            rclass <- BG.getWord16be
            ttl <- BG.getWord32be
            rdlength <- BG.getWord16be
            rdata <- getText $ fromIntegral rdlength
            return $ DNSResourceRecord name rtype rclass ttl rdlength rdata

        dnsNameParser :: BG.Get Text
        dnsNameParser = do
            len <- BG.getWord8
            if len == 0 then return ""
            else do
                name <- getText $ fromIntegral len
                rest <- dnsNameParser
                return $ name <> "." <> rest
        
        getText :: Int -> BG.Get Text
        getText len = do
            decodeLatin1 <$> BG.getByteString len
        
        many :: BG.Get a -> BG.Get [a]
        many p = do
            empty <- BG.isEmpty
            if empty then return []
            else do
                x <- p
                xs <- many p
                return $ x : xs


main :: IO ()
main = do
    sock <- UDP.serverSocket ("127.0.0.1", 2053)
    putStrLn "Server started"
    forever $ do
        (r, clientSock) <- UDP.recvFrom sock
        let message = BG.runGet dnsMessageParser $ BSL.fromStrict r
        print message
        UDP.sendTo sock "" clientSock