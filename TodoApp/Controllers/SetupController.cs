using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TodoApp.Data;

namespace TodoApp.Controllers
{
    [ApiController]
    [Route("api/{controller}")]
    public class SetupController : ControllerBase
    {
        private readonly ApiDbContext _context;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ILogger<SetupController> _logger;

        public SetupController(
            ApiDbContext context,
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            ILogger<SetupController> logger)
        {
            _userManager = userManager;
            _context = context;
            _roleManager = roleManager;
            _logger = logger;
        }

        [HttpGet]
        public IActionResult GetAllRoles()
        {
            var roles = _roleManager.Roles.ToList();
            return Ok(roles);
        }

        [HttpPost]
        public async Task<IActionResult> CreateRole(string name)
        {
            //check role exist
            var roleExist = await _roleManager.RoleExistsAsync(name);

            if (!roleExist)
            {
                //we need to check if the role has been added successfully
                var roleResult = await _roleManager.CreateAsync(new IdentityRole(name));

                if (roleResult.Succeeded)
                {
                    _logger.LogInformation($"The role {name} has been add successfully");

                    return Ok(new
                    {
                        result = "The role {name} has been add successfully"
                    });
                }
                else
                {
                    _logger.LogInformation($"The role {name} has not been added");

                    return BadRequest(new
                    {
                        result = "The role {name} has not been added"
                    });
                }
            }

            return BadRequest(new { error = "Role already exist" });
        }

        [HttpGet("GetAllUsers")]
        public async Task<IActionResult> GetAllUsers()
        {
            var users = await _userManager.Users.ToListAsync();
            return Ok(users);
        }

        [HttpPost("AddUserToRole")]
        public async Task<IActionResult> AddUserToRole(string email, string roleName)
        {
            //check user exist
            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
            {
                _logger.LogInformation($"User not exist");

                return BadRequest(new
                {
                    Error = "User not exist"
                });
            }

            //check role exist
            var role = _roleManager.RoleExistsAsync(roleName);

            if (role == null)
            {
                _logger.LogInformation($"Role not exist");

                return BadRequest(new
                {
                    Error = "Role not exist"
                });
            }

            var result = await _userManager.AddToRoleAsync(user, roleName);

            //check user assign to role

            if (result.Succeeded)
            {
                return Ok(new
                {
                    result = "Success, User has been added to role"
                });
            }
            else
            {
                _logger.LogInformation($"The user enable to add to the role");

                return BadRequest(new
                {
                    Error = "The user enable to add to the role"
                });
            }
        }

        [HttpGet("GetUserRoles")]
        public async Task<IActionResult> GetUserRole(string email)
        {
            //check user exist
            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
            {
                _logger.LogInformation($"User not exist");

                return BadRequest(new
                {
                    Error = "User not exist"
                });
            }

            var roles = await _userManager.GetRolesAsync(user);

            return Ok(roles);
        }

        [HttpPost("RemoveUserFromRole")]
        public async Task<IActionResult> RemoveUserFromRole(string email, string roleName)
        {
            //check user exist
            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
            {
                _logger.LogInformation($"User not exist");

                return BadRequest(new
                {
                    Error = "User not exist"
                });
            }

            //check role exist
            var role = await _roleManager.RoleExistsAsync(roleName);

            if (role == null)
            {
                _logger.LogInformation($"Role not exist");

                return BadRequest(new
                {
                    Error = "Role not exist"
                });
            }

            var result = await _userManager.RemoveFromRoleAsync(user, roleName);

            if (result.Succeeded)
            {
                return Ok(new
                {
                    result = "Success, Role remove from user"
                });
            }
            else
            {
                _logger.LogInformation($"The user enable to remove from role");

                return BadRequest(new
                {
                    Error = "The user enable to remove from role"
                });
            }
        }
    }
}