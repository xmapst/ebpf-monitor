package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"

	"github.com/xmapst/ebpf-monitor/internal/ebpf"
	"github.com/xmapst/ebpf-monitor/internal/metrics"
)

type sApi struct {
	manager   ebpf.IManager
	collector *metrics.SCollector
}

func New(manager ebpf.IManager, collector *metrics.SCollector) *gin.Engine {
	api := &sApi{
		manager:   manager,
		collector: collector,
	}
	router := gin.New()
	router.Use(gin.Recovery(), cors.Default())
	pprof.Register(router)
	api.Register(router)
	return router
}

func (a *sApi) Register(router *gin.Engine) {
	apiV1 := router.Group("/api/v1")
	{
		apiV1.GET("/ping", a.ping)
		apiV1.GET("/metrics", a.getMetricsReport)
		apiV1.PUT("/rule", a.addRule)
		apiV1.DELETE("/rule", a.delRule)
	}
}

func (a *sApi) ping(c *gin.Context) {
	c.String(http.StatusOK, "pong %s", time.Now().Format(time.DateTime))
}

func (a *sApi) getMetricsReport(c *gin.Context) {
	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil {
		page = 1
	}
	pageSize, err := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if err != nil {
		pageSize = 20
	}
	order := c.DefaultQuery("order", "last_seen_at")
	sortDir := c.DefaultQuery("sort", "desc")
	sources := a.collector.GenerateReport(page, pageSize, order, sortDir)
	c.JSON(http.StatusOK, sources)
}

func (a *sApi) addRule(c *gin.Context) {
	sip := c.Query("sip")
	if sip == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "sip is required",
		})
		return
	}
	rate, err := strconv.Atoi(c.Query("rate"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "rate is required",
		})
		return
	}
	if err = a.manager.AddRule(sip, rate); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "ok",
	})
}

func (a *sApi) delRule(c *gin.Context) {
	sip := c.Query("sip")
	if sip == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "sip is required",
		})
		return
	}
	if err := a.manager.DelRule(sip); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "ok",
	})
}
