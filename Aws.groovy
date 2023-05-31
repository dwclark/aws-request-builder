import groovy.transform.Immutable
import groovy.transform.ImmutableOptions
import groovy.transform.ToString
import java.net.URI
import java.net.http.*
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.concurrent.Flow
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import static java.nio.charset.StandardCharsets.UTF_8

class Aws {

    public static final String ACCESS_KEY_ID = 'AWS_ACCESS_KEY_ID'
    public static final String SECRET_ACCESS_KEY = 'AWS_SECRET_ACCESS_KEY'
    public static final String SIGNING_TYPE = 'AWS4-HMAC-SHA256'
    public static final String REQUEST_TYPE = 'aws4_request'
    private static final byte[] REQUET_TYPE_BYTES = REQUEST_TYPE.getBytes(UTF_8.toString())
    public static final String ALGORITHM = 'HmacSHA256'
    public static final List<String> LIST_HEADERS = [ 'host', 'x-amz-content-sha256', 'x-amz-date' ].asImmutable()
    public static final String STR_HEADERS = LIST_HEADERS.join(';')
    public static final List<String> ADDED_HEADERS = ['Authorization', 'x-amz-date', 'x-amz-content-sha256'].asImmutable()
    public static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneId.of('UTC'))
    public static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneId.of('UTC'))
    public static final String NL = '\n'

    private static final ThreadLocal<StringBuilder> _tlHexBuffer = ThreadLocal.withInitial { -> new StringBuilder(1_024) }

    public static String toHex(final byte[] bytes) {
        StringBuilder hexBuffer = _tlHexBuffer.get()
        hexBuffer.length = 0
        for(int i = 0; i < bytes.length; ++i) {
            final int val = bytes[i]
            hexBuffer.append Character.forDigit((val >> 4) & 0xf, 16)
            hexBuffer.append Character.forDigit(val & 0xf, 16)
        }

        hexBuffer.toString()
    }
    
    private static class Sub implements Flow.Subscriber<ByteBuffer> {
        private Flow.Subscription s
        boolean completed = false
        ByteBuffer current = null

        void onComplete() { completed = true }
        void onError(Throwable t) { println t }
        void onNext(ByteBuffer b) { current = b }
        void onSubscribe(Flow.Subscription val) { s = val }
        void next() { s.request(1_024) }
    }

    @Immutable
    private static class Secrets {
        String accessKey, secretAccessKey, region, service
        byte[] regionBytes, serviceBytes, signature

        public String toString() {
            return "Secrets(accessKey: ${accessKey}, secretAccessKey: ${secretAccessKey}, region: ${region}, service: ${service})"
        }
    }

    private static class Data {
        final Mac signer = Mac.getInstance(ALGORITHM)
        final MessageDigest digester = MessageDigest.getInstance('SHA-256')
        final Secrets secrets
        
        String method = "GET"
        HttpRequest.BodyPublisher publisher = HttpRequest.BodyPublishers.noBody()
        boolean expectContinue = false
        Map<String,List<String>> headers = [:]
        Duration timeout = Duration.ofSeconds(86_400L)
        URI uri
        HttpClient.Version version = HttpClient.Version.HTTP_1_1

        private byte[] sign(byte[] key, String toEncrypt) {
            signer.reset()
            signer.init(new SecretKeySpec(key, Aws.ALGORITHM))
            signer.doFinal(toEncrypt.getBytes(UTF_8.toString()))
        }

        Data(Secrets secrets) {
            this.secrets = secrets
            Instant now = Instant.now()
            _requestDateTime = DATE_TIME_FORMATTER.format(now)
            _requestDate = DATE_FORMATTER.format(now)
        }

        Data copy() {
            new Data(secrets).tap {
                method = this.method
                publisher = this.publisher
                expectContinue = this.expectContinue
                headers = this.headers.collectEntries { k, v -> new MapEntry(k,v) }
                timeout = this.timeout
                uri = this.uri
                version = this.version
            }
        }

        Data reset() {
            _canonicalRequest = null
            _hashedCanonicalRequest = null
            _canonicalUri = null
            _canonicalQueryString = null
            _canonicalHeaders = null
            _hashedPayload = null
            _credentialScope = null
            _toSign = null
            _authHeader = null
            Instant now = Instant.now()
            _requestDateTime = DATE_TIME_FORMATTER.format(now)
            _requestDate = DATE_FORMATTER.format(now)
            this
        }

        //work area
        String _canonicalRequest
        String _hashedCanonicalRequest
        String _canonicalUri
        String _canonicalQueryString
        String _canonicalHeaders
        String _hashedPayload
        String _credentialScope
        String _toSign
        String _authHeader
        String _requestDateTime
        String _requestDate

        String getRequestDateTime() { _requestDateTime }
        String getRequestDate() { _requestDate }

        String getCanonicalRequest() {
            if(!_canonicalRequest) {
                _canonicalRequest = [method, canonicalUri, canonicalQueryString,
                                     canonicalHeaders, STR_HEADERS, hashedPayload].join(NL)
            }

            _canonicalRequest
        }

        String getHashedCanonicalRequest() {
            if(!_hashedCanonicalRequest) {
                digester.reset()
                digester.update(canonicalRequest.getBytes(UTF_8.toString()))
                _hashedCanonicalRequest = Aws.toHex(digester.digest())
            }

            _hashedCanonicalRequest
        }

        String getCanonicalUri() {
            if(!_canonicalUri) {
                String path = uri.path
                _canonicalUri = !path ? '/' : path.replace('*', '%2A')
            }

            _canonicalUri
        }

        String getCanonicalQueryString() {
            if(!_canonicalQueryString) {
                _canonicalQueryString = uri.query ? uri.query.split('&').sort().join('&') : ''
            }

            _canonicalQueryString
        }

        String getCanonicalHeaders() {
            if(!_canonicalHeaders) {
                _canonicalHeaders = ["host:${uri.host}", "x-amz-content-sha256:${hashedPayload}", "x-amz-date:${requestDateTime}${NL}"].join(NL)
            }

            _canonicalHeaders
        }

        String getHashedPayload() {
            if(!_hashedPayload) {
                digester.reset()
                Sub sub = new Sub()
                publisher.subscribe(sub)
                while(!sub.completed) {
                    sub.next()
                    if(sub.current)
                        digester.update(sub.current)
                }

                _hashedPayload = Aws.toHex(digester.digest())
            }

            _hashedPayload
        }

        String getCredentialScope() {
            if(!_credentialScope) {
                _credentialScope = "${requestDate}/${secrets.region}/${secrets.service}/${REQUEST_TYPE}"
            }

            _credentialScope
        }

        String getToSign() {
            if(!_toSign) {
                _toSign = [SIGNING_TYPE, requestDateTime, credentialScope, hashedCanonicalRequest].join(NL)
            }

            _toSign
        }

        String getAuthHeader() {
            if(!_authHeader) {
                byte[] key = sign(secrets.signature, requestDate)
                key = sign(key, secrets.region)
                key = sign(key, secrets.service)
                key = sign(key, Aws.REQUEST_TYPE)
                key = sign(key, toSign)
                _authHeader = "${SIGNING_TYPE} Credential=${secrets.accessKey}/${credentialScope}, " +
                    "SignedHeaders=${STR_HEADERS}, Signature=${Aws.toHex(key)}"
            }

            _authHeader
        }


        public String toString() {
            return """Data(secrets: ${secrets},
method: ${method}
expectContinue: ${expectContinue}
headers: ${headers}
timeout: ${timeout}
uri: ${uri}
version: ${version}
canonicalRequest: ${canonicalRequest}
hashedCanonicalRequest: ${hashedCanonicalRequest}
canonicalUri: ${canonicalUri}
canonicalQueryString: ${canonicalQueryString}
canonicalHeaders: ${canonicalHeaders}
hashedPayload: ${hashedPayload}
credentialScope: ${credentialScope}
requestDateTime: ${requestDateTime}
requestDate: ${requestDate}
toSign: ${toSign}
authHeader: ${authHeader}
)"""
        }
    }

    private static class Request extends HttpRequest {
        Optional<HttpRequest.BodyPublisher> publisher
        boolean expectContinue
        HttpHeaders headers
        String method
        Optional<Duration> timeout
        URI uri
        Optional<HttpClient.Version> version

        private Request(Data data) {
            Map awsHeaders = [Authorization: [data.authHeader], 'x-amz-date': [data.requestDateTime], 'x-amz-content-sha256': [data.hashedPayload]]
            publisher = Optional.of(data.publisher)
            expectContinue = data.expectContinue
            headers = HttpHeaders.of(data.headers + awsHeaders, (h1,h2) -> true)
            method = data.method
            timeout = Optional.of(data.timeout)
            uri = data.uri
            version = Optional.of(data.version)
        }

        Optional<HttpRequest.BodyPublisher> bodyPublisher() { publisher }
        boolean expectContinue() { expectContinue }
        HttpHeaders headers() { headers }
        String method() { method }
        Optional<Duration> timeout() { timeout }
        URI uri() { uri }
        Optional<HttpClient.Version> version() { version }
    }
    
    private static class Builder implements HttpRequest.Builder {
        final Data data
        
        private Builder(Data data) {
            this.data = data
        }

        Request build() {
            return new Request(data.copy())
        }

        Builder copy() {
            new Builder(data.copy())
        }

        Builder DELETE() {
            method("DELETE", HttpRequest.BodyPublishers.noBody())
        }

        Builder expectContinue(boolean val) {
            data.expectContinue = val
            this
        }

        Builder GET() {
            method("GET", HttpRequest.BodyPublishers.noBody())
            this
        }

        Builder header(String name, String val) {
            data.headers.get(name, []) << val
            this
        }

        Builder headers(String... vals) {
            if((vals.length % 2) != 0)
                throw new IllegalArgumentException("vals.length % 2 != 0")

            for(int i = 0; i < vals.length; i+=2)
                header(vals[i], vals[i+1])
        }

        Builder method(String val, HttpRequest.BodyPublisher publisher) {
            data.reset().method = val
            data.publisher = publisher
            this
        }

        Builder POST(HttpRequest.BodyPublisher publisher) {
            method("POST", publisher)
        }

        Builder PUT(HttpRequest.BodyPublisher publisher) {
            method("PUT", publisher)
        }

        Builder setHeader(String name, String val) {
            data.headers.name = [val]
            this
        }

        Builder timeout(Duration val) {
            data.timeout = val
            this
        }

        Builder uri(URI val) {
            data.reset().uri = val
            this
        }

        Builder version(HttpClient.Version val) {
            data.version = val
            this
        }
    }

    public static HttpRequest.Builder requestBuilder(Map args) {
        requestBuilder(args.accessKey ?: System.getenv(ACCESS_KEY_ID),
                       args.secretAccessKey ?: System.getenv(SECRET_ACCESS_KEY),
                       args.region, args.service)
    }

    public static HttpRequest.Builder requestBuilder(String region, String service) {
        requestBuilder(System.getenv(ACCESS_KEY_ID), System.getenv(SECRET_ACCESS_KEY),
                       region, service)
    }

    public static HttpRequest.Builder requestBuilder(String accessKey, String secretAccessKey,
                                             String region, String service) {
        Secrets secrets = new Secrets(accessKey, secretAccessKey, region, service,
                                      region.getBytes(UTF_8.toString()), service.getBytes(UTF_8.toString()),
                                      ("AWS4" + secretAccessKey).getBytes(UTF_8.toString()))
        
        new Builder(new Data(secrets))
    }
}
