using System.Security.Cryptography;
using System.Text;
using MySql.Data.MySqlClient;

var builder = WebApplication.CreateBuilder(args);

// CORS så GUI kan kalde via http://localhost:8080
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p
    .AllowAnyOrigin()
    .AllowAnyHeader()
    .AllowAnyMethod()));

var app = builder.Build();
app.UseCors();

var connString = builder.Configuration.GetConnectionString("Default");

string HashPassword(string password)
{
    using var sha256 = SHA256.Create();
    var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
    return Convert.ToBase64String(bytes);
}

app.MapPost("/register", async (UserLogin input) =>
{
    if (string.IsNullOrWhiteSpace(input.Username) || string.IsNullOrWhiteSpace(input.Password))
        return Results.BadRequest("Username and password required.");

    await using var conn = new MySqlConnection(connString);
    await conn.OpenAsync();

    var cmd = new MySqlCommand(
        "INSERT INTO Users (Username, PasswordHash) VALUES (@u, @p)", conn);
    cmd.Parameters.AddWithValue("@u", input.Username);
    cmd.Parameters.AddWithValue("@p", HashPassword(input.Password));

    try
    {
        await cmd.ExecuteNonQueryAsync();
        return Results.Created($"/users/{input.Username}", new { message = "User registered!" });
    }
    catch (MySqlException ex) when (ex.Number == 1062)
    {
        return Results.Conflict("Username already exists.");
    }
});

app.MapPost("/login", async (UserLogin input) =>
{
    await using var conn = new MySqlConnection(connString);
    await conn.OpenAsync();

    var cmd = new MySqlCommand("SELECT PasswordHash FROM Users WHERE Username=@u", conn);
    cmd.Parameters.AddWithValue("@u", input.Username);

    var result = await cmd.ExecuteScalarAsync();
    if (result is null) return Results.Unauthorized();

    var storedHash = (string)result;
    return storedHash == HashPassword(input.Password) ? Results.Ok("Login successful!") : Results.Unauthorized();
});

app.MapGet("/health", () => Results.Ok("OK"));
app.Run();

// 👇 Type-deklarationer SKAL ligge efter top-level statements
public record UserLogin(string Username, string Password);
