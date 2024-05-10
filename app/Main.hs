{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Control.Monad (forever)
import Data.Binary (Word16, Word32, Word8)
import Data.Binary.Get qualified as BG
import Data.Binary.Put qualified as BP
import Data.Bits (Bits (shiftR, (.&.), (.|.)), setBit, shiftL, testBit)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as BSL
import Debug.Trace (trace)
import Network.UDP qualified as UDP
import Numeric (showHex)

traceS :: (Show a) => String -> a -> a
traceS s a = trace (s <> ": " <> show a) a

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
    deriving (Show, Eq)

data DNSResourceType
    = TYPE_ZERO
    | A
    | NS
    | MD
    | MF
    | CNAME
    | SOA
    | MB
    | MG
    | MR
    | NULL
    | WKS
    | PTR
    | HINFO
    | MINFO
    | MX
    | TXT
    deriving (Show, Enum)

data DNSResourceClass
    = CLASS_ZERO
    | IN
    | CS
    | CH
    | HS
    deriving (Show, Enum)

data DNSQuestion = DNSQuestion
    { _qname :: ByteString
    , _qtype :: Word16
    , _qclass :: Word16
    }
    deriving (Show, Eq)

data DNSResourceRecord = DNSResourceRecord
    { _rname :: ByteString
    , _rtype :: Word16
    , _rclass :: Word16
    , _ttl :: Word32
    , _rdata :: ByteString
    }
    deriving (Show, Eq)

data DNSMessage = DNSMessage
    { _header :: DNSHeader
    , _question :: [DNSQuestion]
    , _answer :: [DNSResourceRecord]
    }
    deriving (Show, Eq)

dnsMessageHeaderParser :: BG.Get DNSHeader
dnsMessageHeaderParser = do
    id <- BG.getWord16be
    flags <- BG.getWord16be
    qdcount <- BG.getWord16be
    ancount <- BG.getWord16be
    nscount <- BG.getWord16be
    arcount <- BG.getWord16be
    return $
        DNSHeader
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

dnsMessageParser :: BG.Get DNSMessage
dnsMessageParser = do
    header <- dnsMessageHeaderParser
    questions <- many (fromIntegral $ _qdcount header) dnsQuestionParser
    answer <- many (fromIntegral $ _ancount header) dnsResourceRecordParser
    return $ DNSMessage header questions answer
  where
    dnsQuestionParser :: BG.Get DNSQuestion
    dnsQuestionParser = do
        qname <- dnsNameParser
        qtype <- BG.getWord16be
        DNSQuestion qname qtype <$> BG.getWord16be

    dnsResourceRecordParser :: BG.Get DNSResourceRecord
    dnsResourceRecordParser = do
        rname <- dnsNameParser
        rtype <- BG.getWord16be
        rclass <- BG.getWord16be
        ttl <- BG.getWord32be
        rdlength <- BG.getWord16be
        rdata <- BG.getByteString $ fromIntegral rdlength
        return $
            DNSResourceRecord
                rname
                (toEnum $ fromIntegral rtype)
                (toEnum $ fromIntegral rclass)
                ttl
                rdata

    dnsNameParser :: BG.Get ByteString
    dnsNameParser = do
        len <- BG.getWord8
        if len == 0
            then return ""
            else do
                name <- BG.getByteString $ fromIntegral len
                rest <- dnsNameParser
                if BS.null rest then pure name else pure $ name <> "." <> rest

    many :: Int -> BG.Get a -> BG.Get [a]
    many 0 _ = return []
    many n p = do
        empty <- BG.isEmpty
        if empty
            then return []
            else do
                x <- p
                xs <- many (n - 1) p
                return $ x : xs

encodeDnsMessage :: DNSMessage -> ByteString
encodeDnsMessage = BSL.toStrict . BP.runPut . dnsMessageBuilder
  where
    dnsMessageBuilder :: DNSMessage -> BP.Put
    dnsMessageBuilder (DNSMessage header questions answers) = do
        dnsHeaderBuilder header
        mapM_ dnsQuestionBuilder questions
        mapM_ dnsResourceRecordBuilder answers

    dnsHeaderBuilder :: DNSHeader -> BP.Put
    dnsHeaderBuilder (DNSHeader id qr opcode aa tc rd ra z rcode qdcount ancount nscount arcount) = do
        BP.putWord16be id
        BP.putWord16be $ flags qr opcode aa tc rd ra z rcode
        BP.putWord16be qdcount
        BP.putWord16be ancount
        BP.putWord16be nscount
        BP.putWord16be arcount
      where
        flags :: Bool -> Word8 -> Bool -> Bool -> Bool -> Bool -> Word8 -> Word8 -> Word16
        flags qr opcode aa tc rd ra z rcode =
            (if qr then 0 `setBit` 15 else 0)
                .|. fromIntegral opcode `shiftL` 11
                .|. (if aa then 0 `setBit` 10 else 0)
                .|. (if tc then 0 `setBit` 9 else 0)
                .|. (if rd then 0 `setBit` 8 else 0)
                .|. (if ra then 0 `setBit` 7 else 0)
                .|. fromIntegral z .&. (0x7 `shiftL` 4)
                .|. fromIntegral rcode .&. 0xF

    dnsQuestionBuilder :: DNSQuestion -> BP.Put
    dnsQuestionBuilder (DNSQuestion qname qtype qclass) = do
        dnsNameBuilder qname
        BP.putWord16be qtype
        BP.putWord16be qclass

    dnsResourceRecordBuilder :: DNSResourceRecord -> BP.Put
    dnsResourceRecordBuilder (DNSResourceRecord rname rtype rclass ttl rdata) = do
        dnsNameBuilder rname
        BP.putWord16be $ fromIntegral $ fromEnum rtype
        BP.putWord16be $ fromIntegral $ fromEnum rclass
        BP.putWord32be ttl
        BP.putWord16be (fromIntegral $ BS.length rdata)
        BP.putByteString rdata

    dnsNameBuilder :: ByteString -> BP.Put
    dnsNameBuilder name = do
        let parts = BS.split (fromIntegral $ fromEnum '.') name
        mapM_
            ( \part -> do
                BP.putWord8 $ fromIntegral $ BS.length part
                BP.putByteString part
            )
            parts
        BP.putWord8 0

main :: IO ()
main = do
    sock <- UDP.serverSocket ("127.0.0.1", 2053)
    putStrLn "Server started"
    forever $ do
        (r, clientSock) <- UDP.recvFrom sock
        let header = BG.runGet dnsMessageHeaderParser $ BSL.fromStrict r
        let message =
                DNSMessage
                    ( DNSHeader
                        { _id = _id header
                        , _qr = True
                        , _opcode = _opcode header
                        , _aa = False
                        , _tc = False
                        , _rd = _rd header
                        , _ra = False
                        , _z = 0
                        , _rcode = if _opcode header == 0 then 0 else 4
                        , _qdcount = 1
                        , _ancount = 1
                        , _nscount = 0
                        , _arcount = 0
                        }
                    )
                    [ DNSQuestion
                        { _qname = "codecrafters.io"
                        , _qtype = fromIntegral $ fromEnum A
                        , _qclass = fromIntegral $ fromEnum IN
                        }
                    ]
                    [ DNSResourceRecord
                        { _rname = "codecrafters.io"
                        , _rtype = fromIntegral $ fromEnum A
                        , _rclass = fromIntegral $ fromEnum IN
                        , _ttl = 60
                        , _rdata = BS.pack [8, 8, 8, 8]
                        }
                    ]
        let resp = encodeDnsMessage message
        -- print $ BG.runGet dnsMessageParser (BSL.fromStrict resp)
        -- print message
        -- print $ prettyPrint $ encodeDnsMessage $ BG.runGet dnsMessageParser $ BSL.fromStrict resp
        -- print $ prettyPrint resp
        -- error "error"
        -- error $ show header
        UDP.sendTo sock resp clientSock

prettyPrint :: ByteString -> String
prettyPrint = concatMap (`showHex` "") . BS.unpack
