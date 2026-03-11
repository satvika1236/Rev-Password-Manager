package com.revature.passwordmanager.service.security;

import com.revature.passwordmanager.util.ClientIpUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class GeoLocationServiceTest {

  private GeoLocationService geoLocationService;
  private ClientIpUtil clientIpUtil;

  @BeforeEach
  void setUp() {
    clientIpUtil = new ClientIpUtil();
    geoLocationService = new GeoLocationService(clientIpUtil);
  }

  @Test
  void getLocationFromIp_Null_ShouldReturnLocalNetwork() {
    assertEquals("Local Network", geoLocationService.getLocationFromIp(null));
  }

  @Test
  void getLocationFromIp_Empty_ShouldReturnLocalNetwork() {
    assertEquals("Local Network", geoLocationService.getLocationFromIp(""));
  }

  @Test
  void getLocationFromIp_Localhost_ShouldReturnLocalNetwork() {
    assertEquals("Local Network", geoLocationService.getLocationFromIp("127.0.0.1"));
  }

  @Test
  void getLocationFromIp_IPv6Localhost_ShouldReturnLocalNetwork() {
    assertEquals("Local Network", geoLocationService.getLocationFromIp("0:0:0:0:0:0:0:1"));
  }

  @Test
  void getLocationFromIp_PrivateIP_10_ShouldReturnLocalNetwork() {
    assertEquals("Local Network", geoLocationService.getLocationFromIp("10.0.0.1"));
  }

  @Test
  void getLocationFromIp_PrivateIP_192_ShouldReturnLocalNetwork() {
    assertEquals("Local Network", geoLocationService.getLocationFromIp("192.168.1.100"));
  }

  @Test
  void getLocationFromIp_PrivateIP_172_ShouldReturnLocalNetwork() {
    assertEquals("Local Network", geoLocationService.getLocationFromIp("172.16.0.1"));
  }

  @Test
  void getLocationFromIp_PublicIP_ShouldReturnSimulatedLocation() {
    assertEquals("City, Country (Simulated)", geoLocationService.getLocationFromIp("8.8.8.8"));
  }

  @Test
  void getLocationFromIp_Unknown_ShouldReturnUnknown() {
    assertEquals("Unknown", geoLocationService.getLocationFromIp("unknown"));
  }
}
