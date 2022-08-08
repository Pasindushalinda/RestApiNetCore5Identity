using System.Text;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using TodoApp.Configuration;
using TodoApp.Data.Dtos;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using TodoApp.Data;
using Microsoft.EntityFrameworkCore;

namespace TodoApp.Controllers
{
    [ApiController]
    [Route("api/{controller}")]
    public class AuthManagementController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JwtConfig _jwtConfig;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ILogger<AuthManagementController> _logger;
        private readonly TokenValidationParameters _tokenValidationParams;
        private readonly ApiDbContext _apiDbContext;

        public AuthManagementController(
            UserManager<IdentityUser> userManager,
            IOptionsMonitor<JwtConfig> optionsMonitor,
            RoleManager<IdentityRole> roleManager,
            ILogger<AuthManagementController> logger,
            TokenValidationParameters tokenValidationParameters,
            ApiDbContext apiDbContext)
        {
            _userManager = userManager;
            _jwtConfig = optionsMonitor.CurrentValue;
            _roleManager = roleManager;
            _logger = logger;
            _tokenValidationParams = tokenValidationParameters;
            _apiDbContext = apiDbContext;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationDto user)
        {
            if (ModelState.IsValid)
            {
                var existingUser = await _userManager.FindByEmailAsync(user.Email);

                if (existingUser != null)
                {
                    return BadRequest(new UserRegistrationResponseDto()
                    {
                        Errors = new List<string>(){
                            "Email already use"
                        },
                        Success = false
                    });
                }
            }

            var newUser = new IdentityUser
            {
                Email = user.Email,
                UserName = user.Username
            };

            var isCreated = await _userManager.CreateAsync(newUser, user.Password);

            if (isCreated.Succeeded)
            {
                var resultRoleAddition = await _userManager.AddToRoleAsync(newUser, "AppUser");

                var jwtToken = await GenarateJwtToken(newUser);

                return Ok(jwtToken);
            }
            else
            {
                return BadRequest(new UserRegistrationResponseDto()
                {
                    Errors = isCreated.Errors.Select(x => x.Description).ToList(),
                    Success = false
                });
            }

            return BadRequest(new UserRegistrationResponseDto()
            {
                Errors = new List<string>(){
                    "Invalid payload"
                },
                Success = false
            });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserLoginDto user)
        {
            if (ModelState.IsValid)
            {
                var existingUser = await _userManager.FindByEmailAsync(user.Email);

                if (existingUser == null)
                {
                    return BadRequest(new UserRegistrationResponseDto()
                    {
                        Errors = new List<string>(){
                            "Invalid login request"
                        },
                        Success = false
                    });
                }

                var isCorrect = await _userManager.CheckPasswordAsync(existingUser, user.Password);

                if (!isCorrect)
                {
                    return BadRequest(new UserRegistrationResponseDto()
                    {
                        Errors = new List<string>(){
                            "Invalid login request"
                        },
                        Success = false
                    });
                }

                var jwtToken = await GenarateJwtToken(existingUser);

                return Ok(jwtToken);
            }

            return BadRequest(new UserRegistrationResponseDto()
            {
                Errors = new List<string>(){
                    "Invalid payload"
                },
                Success = false
            });
        }

        [HttpPost("RefreshToken")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenRequest tokenRequest)
        {
            if (ModelState.IsValid)
            {
                var result = await VerifyAndGenarateToken(tokenRequest);

                if (result == null)
                {
                    return BadRequest(new UserRegistrationResponseDto()
                    {
                        Errors = new List<string>(){
                    "Invalid token"
                    },
                        Success = false
                    });
                }

                return Ok(result);
            }

            return BadRequest(new UserRegistrationResponseDto()
            {
                Errors = new List<string>(){
                    "Invalid payload"
                },
                Success = false
            });
        }

        private async Task<List<Claim>> GetAllValidClaims(IdentityUser user)
        {
            var _option = new IdentityOptions();

            var claims = new List<Claim>
            {
                new Claim("Id",user.Id),
                new Claim(JwtRegisteredClaimNames.Email,user.Email),
                new Claim(JwtRegisteredClaimNames.Sub,user.Email),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
            };

            //Getting the claims that we have assigned to the user
            var userClaims = await _userManager.GetClaimsAsync(user);
            claims.AddRange(userClaims);

            //Get user roles and add it to the claims
            var userRoles = await _userManager.GetRolesAsync(user);

            foreach (var userRole in userRoles)
            {
                var role = await _roleManager.FindByNameAsync(userRole);
                if (role != null)
                {
                    claims.Add(new Claim(ClaimTypes.Role, userRole));

                    var roleClaims = await _roleManager.GetClaimsAsync(role);
                    foreach (var roleClaim in roleClaims)
                    {
                        claims.Add(roleClaim);
                    }
                }
            }

            return claims;
        }

        private async Task<AuthResult> GenarateJwtToken(IdentityUser user)
        {
            //A SecurityTokenHandler designed for creating and validating Json Web Tokens
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);

            var claims = await GetAllValidClaims(user);

            //This is a place holder for all the attributes related to the issued token.
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddSeconds(30),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);

            var refreshToken = new RefreshToken()
            {
                JwtId = token.Id,
                IsUsed = false,
                IsRevoked = false,
                UserId = user.Id,
                AddedDate = DateTime.UtcNow,
                ExpiryDate = DateTime.UtcNow.AddMonths(6),
                Token = RandomString(5) + Guid.NewGuid()
            };

            await _apiDbContext.RefreshTokens.AddAsync(refreshToken);
            await _apiDbContext.SaveChangesAsync();

            return new AuthResult
            {
                Success = true,
                RefreshToken = refreshToken.Token,
                Token = jwtToken
            };
        }

        private string RandomString(int length)
        {
            var random = new Random();
            var chars = "ABCD1";
            return new string(Enumerable.Repeat(chars, length)
                .Select(x => x[random.Next(x.Length)]).ToArray());
        }

        private async Task<AuthResult> VerifyAndGenarateToken(TokenRequest tokenRequest)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            try
            {
                //validation 1-Validate jwt token format
                _tokenValidationParams.ValidateLifetime = false;

                var tokenInVerification = jwtTokenHandler.ValidateToken(
                    tokenRequest.Token,
                    _tokenValidationParams,
                    out var validatedToken);

                _tokenValidationParams.ValidateLifetime = true;

                //validation 2-Validate encryption algo
                if (validatedToken is JwtSecurityToken jwtSecurityToken)
                {
                    var result = jwtSecurityToken.Header.Alg.Equals(
                        SecurityAlgorithms.HmacSha256Signature,
                        StringComparison.InvariantCultureIgnoreCase);

                    if (!result) return null;
                }

                //validation 3-Expire date
                var utcExpiryDate = long.Parse(tokenInVerification
                    .Claims
                    .FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp)
                    .Value);

                var expiryDate = UnixTimeStampToDateTime(utcExpiryDate);

                if (expiryDate > DateTime.UtcNow)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>(){
                            "Token not expire yet"
                        }
                    };
                }

                //validation 4-existence of the token
                var storedToken = await _apiDbContext
                    .RefreshTokens
                    .FirstOrDefaultAsync(x => x.Token == tokenRequest.RefreshToken);

                if (storedToken == null)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>(){
                            "Token does not exist"
                        }
                    };
                }

                //validation 5-if used
                if (storedToken.IsUsed)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>(){
                            "Token has been used"
                        }
                    };
                }

                //validation 6-if revoke
                if (storedToken.IsRevoked)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>(){
                            "Token has been revoke"
                        }
                    };
                }

                //validation 7-id
                var jti = tokenInVerification
                    .Claims
                    .FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti)
                    .Value;

                if (storedToken.JwtId != jti)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>(){
                            "Token does not match"
                        }
                    };
                }

                //update current token
                storedToken.IsUsed = true;
                _apiDbContext.RefreshTokens.Update(storedToken);
                await _apiDbContext.SaveChangesAsync();

                //generate new token
                var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);
                return await GenarateJwtToken(dbUser);
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        private DateTime UnixTimeStampToDateTime(long unixTimeStamp)
        {
            var dateTimeVal = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            return dateTimeVal.AddSeconds(unixTimeStamp).ToLocalTime();
        }
    }
}