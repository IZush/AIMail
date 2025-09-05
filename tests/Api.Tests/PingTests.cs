// using System.Net;
// using Microsoft.AspNetCore.Mvc.Testing;
// using Xunit;
// using FluentAssertions;

// public class PingTests : IClassFixture<WebApplicationFactory<Program>>
// {
//     private readonly WebApplicationFactory<Program> _factory;
//     public PingTests(WebApplicationFactory<Program> factory) => _factory = factory;

//     [Fact]
//     public async Task Ping_ReturnsOk()
//     {
//         var client = _factory.CreateClient();
//         var res = await client.GetAsync("/api/v1/ping");
//         res.StatusCode.Should().Be(HttpStatusCode.OK);
//     }
// }