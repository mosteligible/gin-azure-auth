package azauth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func Auth(ctx *gin.Context) {
	tokenString := ctx.GetHeader("Authorization")
	if tokenString == "" {
		ctx.JSON(http.StatusForbidden, map[string]string{"detail": "Invalid Token!"})
		ctx.Abort()
		return
	}

	tokenString = strings.ReplaceAll(tokenString, "Bearer ", "")
	uc, err := oauth.ParseAccessToken(tokenString)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusForbidden, map[string]string{"detail": "Invalid token!"})
		return
	}
	ctx.Set("user", uc)
	ctx.Next()
}
