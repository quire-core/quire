package api

import (
	"github.com/go-chi/chi/v5"
	"github.com/quire-core/quire/internal/api/handlers/auth"
	"github.com/quire-core/quire/internal/api/middlewares"
)

// APIServer returns the root HTTP router with all Quire API routes mounted.
func APIServer() *chi.Mux {
	router := chi.NewRouter()

	router.Route("/api/v1", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			r.Post("/register", auth.RegisterHandler)
			r.Post("/login", auth.LoginHandler)
			r.Post("/refresh", auth.RefreshHandler)

			r.With(middlewares.AuthMiddleware).Get("/me", auth.MeHandler)
		})
	})

	return router
}
