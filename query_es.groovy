import java.net.http.*
import groovy.json.*

final host = 'https://search-davidclark-uyn3nf2dxaxr37uxgjqayp2jma.us-east-1.es.amazonaws.com'
final builder = Aws.requestBuilder(service: 'es', region: 'us-east-1')
final client = HttpClient.newBuilder().build()

def json = new JsonBuilder(name: "Wakeland HS", description: "Frisco Unified",
                           street: "123 Legacy", city: "Frisco", state: "TX", zip: "75033",
                           tags: [ "Good Faculty", "Good Sports" ], rating: 4.5)

def updateBuilder = builder.copy()
    .uri(new URI("${host}/school/_doc/10"))
    .header("Content-Type", "application/json")
    .PUT(HttpRequest.BodyPublishers.ofString(json.toString()))

println client.send(updateBuilder.build(), HttpResponse.BodyHandlers.ofString()).body()

final queryBuilder = builder.copy()
    .uri(new URI("${host}/school/_search"))
    .GET()

println client.send(queryBuilder.build(), HttpResponse.BodyHandlers.ofString()).body()

def specific = builder.copy()
    .uri(new URI("${host}/school/_doc/10"))
    .GET()

println client.send(specific.build(), HttpResponse.BodyHandlers.ofString()).body()
