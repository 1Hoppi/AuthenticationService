using Grpc.Core;
using Microsoft.Extensions.Options;

public class ValidateCommandHandler
{
    private readonly IOptionsMonitor<JwtSettings> _options;
    private readonly IJwtValidator _jwtValidator;

    public ValidateCommandHandler(
        IOptionsMonitor<JwtSettings> options,
        IJwtValidator jwtValidator)
    {
        _options = options;
        _jwtValidator = jwtValidator;
    }

    public async Task<ValidationResultDto> Validate(AccessTokenDto request, ServerCallContext context)
    {
        try
        {
            _jwtValidator.ValidateToken(request.AccessToken, _options.CurrentValue.AccessAudience);
            await _jwtValidator.ValidateAccessRevocation(request.AccessToken);
        }
        catch (RpcException)
        {
            return new ValidationResultDto
            {
                IsValid = false,
            };
        }

        return new ValidationResultDto
        {
            IsValid = true,
        };
    }
}