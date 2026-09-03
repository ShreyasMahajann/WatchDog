package com.watchdog.app.wpa.wpasec

import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files

class WpaSecClientTest {

    private lateinit var server: MockWebServer
    private lateinit var client: WpaSecClient

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
        client = WpaSecClient(baseUrl = server.url("/").toString())
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun `results parse bssid ssid and password and normalize mac`() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                "aabbccddeeff:112233445566:HomeWiFi:hunter2\n" +
                    "001122334455:665544332211:My:Net:secret\n",
            ),
        )
        val res = client.fetchResults("deadbeefdeadbeefdeadbeefdeadbeef")
        assertTrue(res is ResultsResponse.Success)
        val entries = (res as ResultsResponse.Success).entries
        assertEquals(2, entries.size)
        assertEquals("aabbccddeeff", entries[0].bssidHex)
        assertEquals("HomeWiFi", entries[0].ssid)
        assertEquals("hunter2", entries[0].password)
        // SSID containing ':' preserved, password is the trailing field.
        assertEquals("My:Net", entries[1].ssid)
        assertEquals("secret", entries[1].password)

        val req: RecordedRequest = server.takeRequest()
        assertEquals("/?api&dl=1", req.path)
        assertEquals("key=deadbeefdeadbeefdeadbeefdeadbeef", req.getHeader("Cookie"))
    }

    @Test
    fun `html response is treated as invalid key`() = runBlocking {
        server.enqueue(MockResponse().setBody("<!DOCTYPE html><html><body>get your key</body></html>"))
        val res = client.fetchResults("badkey")
        assertTrue(res is ResultsResponse.InvalidKey)
    }

    @Test
    fun `empty body is a valid empty result`() = runBlocking {
        server.enqueue(MockResponse().setBody(""))
        val res = client.fetchResults("validkeybutnothingcracked")
        assertTrue(res is ResultsResponse.Success)
        assertEquals(0, (res as ResultsResponse.Success).entries.size)
    }

    @Test
    fun `upload posts multipart file with key cookie and succeeds on 200`() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(200).setBody("ok"))
        val tmp: File = Files.createTempFile("hs", ".pcap").toFile().apply { writeBytes(byteArrayOf(1, 2, 3, 4)) }
        val res = client.upload(tmp, "mykey123")
        assertTrue(res is UploadResult.Success)

        val req = server.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("key=mykey123", req.getHeader("Cookie"))
        val body = req.body.readUtf8()
        assertTrue(body.contains("name=\"file\""))
        assertTrue(body.contains(tmp.name))
    }

    @Test
    fun `upload maps server error to rejected`() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(500).setBody("nope"))
        val tmp = Files.createTempFile("hs", ".pcap").toFile().apply { writeBytes(byteArrayOf(1)) }
        val res = client.upload(tmp, "k")
        assertTrue(res is UploadResult.Rejected)
    }

    @Test
    fun `normalizeMac strips separators and lowercases`() {
        assertEquals("aabbccddeeff", WpaSecClient.normalizeMac("AA:BB:CC:DD:EE:FF"))
    }
}
