{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Control.Monad (foldM, forever)
import Data.Binary (Word16, Word32, Word8)
import Data.Binary.Get qualified as BG
import Data.Binary.Put qualified as BP
import Data.Bits (Bits (shiftR, (.&.), (.|.)), setBit, shiftL, testBit)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as BSL
import Debug.Trace (trace, traceShow)
import Network.UDP qualified as UDP
import Numeric (showHex)
import System.Environment (getArgs)

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
    , _questions :: [DNSQuestion]
    , _answers :: [DNSResourceRecord]
    }
    deriving (Show, Eq)

{-
 >>> aaa
-}
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

{-
>>> let input = "K\183\SOH\NUL\NUL\STX\NUL\NUL\NUL\NUL\NUL\NUL\ETXabc\DC1longassdomainname\ETXcom\NUL\NUL\SOH\NUL\SOH\ETXdef\192\DLE\NUL\SOH\NUL\SOH"
>>> BG.runGet (dnsMessageParser input) input
DNSMessage {_header = DNSHeader {_id = 19383, _qr = False, _opcode = 0, _aa = False, _tc = False, _rd = True, _ra = False, _z = 0, _rcode = 0, _qdcount = 2, _ancount = 0, _nscount = 0, _arcount = 0}, _questions = [DNSQuestion {_qname = "abc.longassdomainname.com", _qtype = 1, _qclass = 1},DNSQuestion {_qname = "def.longassdomainname.com", _qtype = 1, _qclass = 1}], _answers = []}
-}
dnsMessageParser :: ByteString -> BG.Get DNSMessage
dnsMessageParser input = do
    header <- dnsMessageHeaderParser
    questions <- many (fromIntegral $ _qdcount header) (dnsQuestionParser input)
    answer <- many (fromIntegral $ _ancount header) (dnsResourceRecordParser input)
    return $ DNSMessage header questions answer
  where
    dnsQuestionParser :: ByteString -> BG.Get DNSQuestion
    dnsQuestionParser input = do
        qname <- dnsNameParser input
        qtype <- BG.getWord16be
        DNSQuestion qname qtype <$> BG.getWord16be

    dnsResourceRecordParser :: ByteString -> BG.Get DNSResourceRecord
    dnsResourceRecordParser input = do
        rname <- dnsNameParser input
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

    dnsLabelParser :: ByteString -> BG.Get ByteString
    dnsLabelParser input = do
        len <- BG.getWord8
        if len == 0
            then pure ""
            else
                if (len .&. 0xC0) == 0xC0
                    then do
                        offset <- BG.getWord8
                        let offset' = (((fromIntegral :: Word8 -> Word16) len .&. 0x3F) `shiftL` 8) .|. fromIntegral offset
                        pure $
                            BG.runGet
                                ( do
                                    BG.skip $ fromIntegral offset'
                                    dnsNameParser input
                                )
                                (BSL.fromStrict input)
                    else do
                        BG.getByteString $ fromIntegral len

    dnsNameParser :: ByteString -> BG.Get ByteString
    dnsNameParser input = do
        len <- BG.getWord8
        if len == 0
            then pure ""
            else
                if (len .&. 0xC0) == 0xC0
                    then do
                        offset <- BG.getWord8
                        let offset' = (((fromIntegral :: Word8 -> Word16) len .&. 0x3F) `shiftL` 8) .|. fromIntegral offset
                        pure $
                            BG.runGet
                                ( do
                                    BG.skip $ fromIntegral offset'
                                    dnsNameParser input
                                )
                                (BSL.fromStrict input)
                    else do
                        label <- BG.getByteString $ fromIntegral len
                        rest <- dnsNameParser input
                        if BS.null rest
                            then pure label
                            else pure $ label <> "." <> rest

    many :: (Show a) => Int -> BG.Get a -> BG.Get [a]
    many 0 _ = pure []
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

createClient :: String -> IO UDP.UDPSocket
createClient address =
    let (host, _ : port) = break (== ':') address
     in UDP.clientSocket host port False

parseDNSMessage :: ByteString -> DNSMessage
parseDNSMessage input =
    BG.runGet (dnsMessageParser input) $ BSL.fromStrict input

sendAndRecv :: UDP.UDPSocket -> DNSMessage -> IO DNSMessage
sendAndRecv sock req = do
    UDP.send sock $ encodeDnsMessage req
    resp <- UDP.recv sock
    pure $ parseDNSMessage resp

main :: IO ()
main = do
    sock <- UDP.serverSocket ("127.0.0.1", 2053)
    putStrLn "Server started"
    args <- getArgs
    case args of
        ["--resolver", address] ->
            forever $ do
                (input, clientSock) <- UDP.recvFrom sock
                let inputMessage = parseDNSMessage input
                forwardServerClient <- createClient address
                answers <-
                    reverse
                        <$> foldM
                            ( \answers question -> do
                                let h = _header inputMessage
                                -- FIXME: Do we need handle id here? because UDP packet might not in order
                                let h' = h{_qdcount = 1}
                                resp <- sendAndRecv forwardServerClient (DNSMessage h' [question] [])
                                pure $ head (_answers resp) : answers
                            )
                            []
                            (_questions inputMessage)
                let h = _header inputMessage
                let h' = h{_ancount = fromIntegral $ length answers, _qr = True}
                UDP.sendTo sock (encodeDnsMessage $ inputMessage{_header = h', _answers = answers}) clientSock
        _ ->
            forever $ do
                (input, clientSock) <- UDP.recvFrom sock
                let inputMessage = parseDNSMessage input
                let inputHeader = _header inputMessage
                let message =
                        DNSMessage
                            ( DNSHeader
                                { _id = _id inputHeader
                                , _qr = True
                                , _opcode = _opcode inputHeader
                                , _aa = False
                                , _tc = False
                                , _rd = _rd inputHeader
                                , _ra = False
                                , _z = 0
                                , _rcode = if _opcode inputHeader == 0 then 0 else 4
                                , _qdcount = fromIntegral $ length $ _questions inputMessage
                                , _ancount = fromIntegral $ length $ _questions inputMessage
                                , _nscount = 0
                                , _arcount = 0
                                }
                            )
                            ( fmap
                                ( \(DNSQuestion name _ _) ->
                                    DNSQuestion
                                        { _qname = name
                                        , _qtype = fromIntegral $ fromEnum A
                                        , _qclass = fromIntegral $ fromEnum IN
                                        }
                                )
                                (_questions inputMessage)
                            )
                            ( fmap
                                ( \(DNSQuestion{_qname = name}) ->
                                    DNSResourceRecord
                                        { _rname = name
                                        , _rtype = fromIntegral $ fromEnum A
                                        , _rclass = fromIntegral $ fromEnum IN
                                        , _ttl = 60
                                        , _rdata = BS.pack [8, 8, 8, 8]
                                        }
                                )
                                (_questions inputMessage)
                            )
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
