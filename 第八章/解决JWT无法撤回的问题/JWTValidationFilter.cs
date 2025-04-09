using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Caching.Memory;
using System.Net;
using System.Security.Claims;

public class JWTValidationFilter : IAsyncActionFilter
{
    private IMemoryCache memCache;
    private UserManager<User> userMgr;

    public JWTValidationFilter(IMemoryCache memCache, UserManager<User> userMgr)
    {
        this.memCache = memCache;
        this.userMgr = userMgr;
    }

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var claimUserId = context.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier);
        //对于登录接口等没有登录的，直接跳过
        if (claimUserId == null)
        {
            await next();
            return;
        }
        long userId = long.Parse(claimUserId!.Value);
        string cacheKey = $"JWTValidationFilter.UserInfo.{userId}";
        User user = await memCache.GetOrCreateAsync(cacheKey, async e => {
            e.AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(5);
            return await userMgr.FindByIdAsync(userId.ToString());
        });
        if (user == null)
        {
            var result = new ObjectResult($"UserId({userId}) not found");
            result.StatusCode = (int)HttpStatusCode.Unauthorized;
            context.Result = result;
            return;
        }
        //请求到达时，JWT中间件自动解析Authorization头中的token验证签名、有效期等将token中的claims转换为ClaimsPrincipal 验证成功后，中间件将ClaimsPrincipal对象赋给HttpContext.User
        //通过jwt的user这时候才能正常的访问这个参数。
        var claimVersion = context.HttpContext.User.FindFirst(ClaimTypes.Version);
        //jwt中保存的版本号
        long jwtVerOfReq = long.Parse(claimVersion!.Value);
        //由于内存缓存等导致的并发问题，
        //假如集群的A服务器中缓存保存的还是版本为5的数据，但客户端提交过来的可能已经是版本号为6的数据。因此只要是客户端提交的版本号>=服务器上取出来（可能是从Db，也可能是从缓存）的版本号，那么也是可以的
        if (jwtVerOfReq >= user.JWTVersion)
        {
            await next();
        }
        else
        {
            var result = new ObjectResult($"JWTVersion mismatch");
            result.StatusCode = (int)HttpStatusCode.Unauthorized;
            context.Result = result;
            return;
        }
    }
}
