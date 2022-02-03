package x

import (
	"github.com/julienschmidt/httprouter"
	"net/http"
)

type RouterAdmin struct {
	*httprouter.Router
}

type RouterPublic struct {
	*httprouter.Router
}

func NewRouterPublic() *RouterPublic {
	return &RouterPublic{
		Router: httprouter.New(),
	}
}

func NewRouterAdmin() *RouterAdmin {
	return &RouterAdmin{
		Router: httprouter.New(),
	}
}

const RoutePathPrefix = "/kratos-public"

func effectivePath(path string) string {
	return RoutePathPrefix + path
}

// GET is a shortcut for router.Handle(http.MethodGet, path, handle)
func (r *RouterPublic) GET(path string, handle httprouter.Handle) {
	r.Handle(http.MethodGet, effectivePath(path), NoCacheHandler(handle))
}

// HEAD is a shortcut for router.Handle(http.MethodHead, path, handle)
func (r *RouterPublic) HEAD(path string, handle httprouter.Handle) {
	r.Handle(http.MethodHead, effectivePath(path), NoCacheHandler(handle))
}

// OPTIONS is a shortcut for router.Handle(http.MethodOptions, path, handle)
func (r *RouterPublic) OPTIONS(path string, handle httprouter.Handle) {
	r.Handle(http.MethodOptions, effectivePath(path), handle)
}

// POST is a shortcut for router.Handle(http.MethodPost, path, handle)
func (r *RouterPublic) POST(path string, handle httprouter.Handle) {
	r.Handle(http.MethodPost, effectivePath(path), NoCacheHandler(handle))
}

// PUT is a shortcut for router.Handle(http.MethodPut, path, handle)
func (r *RouterPublic) PUT(path string, handle httprouter.Handle) {
	r.Handle(http.MethodPut, effectivePath(path), NoCacheHandler(handle))
}

// PATCH is a shortcut for router.Handle(http.MethodPatch, path, handle)
func (r *RouterPublic) PATCH(path string, handle httprouter.Handle) {
	r.Handle(http.MethodPatch, effectivePath(path), NoCacheHandler(handle))
}

// DELETE is a shortcut for router.Handle(http.MethodDelete, path, handle)
func (r *RouterPublic) DELETE(path string, handle httprouter.Handle) {
	r.Handle(http.MethodDelete, effectivePath(path), NoCacheHandler(handle))
}

func (r *RouterPublic) Lookup(method, path string) (httprouter.Handle, httprouter.Params, bool) {
	return r.Router.Lookup(method, effectivePath(path))
}
