package com.poc.resourceserver.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Web layer tests for MovieController — JWT-protected resource.
 */
@WebMvcTest(MovieController.class)
@DisplayName("MovieController — JWT Protected Movie Endpoint")
class MovieControllerTest {

    @Autowired
    private MockMvc mockMvc;

    // ----------------------------------------------------------------
    // Helper: build a mock JWT with standard claims
    // ----------------------------------------------------------------
    private SecurityMockMvcRequestPostProcessors.JwtRequestPostProcessor mockJwt() {
        return jwt()
                .jwt(builder -> builder
                        .subject("resource-client")
                        .issuer("http://localhost:9000")
                        .issuedAt(Instant.now())
                        .expiresAt(Instant.now().plusSeconds(3600))
                        .claim("scope", "movies:read")
                        .header("kid", "auth-server-key-01")
                        .header("alg", "RS256")
                );
    }

    @Nested
    @DisplayName("GET /api/movies — provideMovieDetails")
    class ProvideMovieDetailsTests {

        @Test
        @DisplayName("Should return 401 when no JWT is provided")
        void shouldReturn401WhenNoJwt() throws Exception {
            mockMvc.perform(get("/api/movies"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Should return 200 and all 10 movies with valid JWT")
        void shouldReturn10MoviesWithValidJwt() throws Exception {
            mockMvc.perform(get("/api/movies").with(mockJwt()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.totalMovies").value(10))
                    .andExpect(jsonPath("$.movies").isArray())
                    .andExpect(jsonPath("$.movies.length()").value(10));
        }

        @Test
        @DisplayName("Response should include requestedBy from JWT subject")
        void shouldIncludeRequestedBy() throws Exception {
            mockMvc.perform(get("/api/movies").with(mockJwt()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.requestedBy").value("resource-client"));
        }

        @Test
        @DisplayName("Response should include tokenKid from JWT header")
        void shouldIncludeTokenKid() throws Exception {
            mockMvc.perform(get("/api/movies").with(mockJwt()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.tokenKid").value("auth-server-key-01"));
        }

        @Test
        @DisplayName("Response should include issuedBy from JWT issuer")
        void shouldIncludeIssuedBy() throws Exception {
            mockMvc.perform(get("/api/movies").with(mockJwt()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.issuedBy").value("http://localhost:9000"));
        }

        @Test
        @DisplayName("Movies should contain required fields: title, genre, director, imdbRating")
        void moviesShouldContainRequiredFields() throws Exception {
            mockMvc.perform(get("/api/movies").with(mockJwt()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.movies[0].title").isNotEmpty())
                    .andExpect(jsonPath("$.movies[0].genre").isNotEmpty())
                    .andExpect(jsonPath("$.movies[0].director").isNotEmpty())
                    .andExpect(jsonPath("$.movies[0].imdbRating").isNumber());
        }
    }

    @Nested
    @DisplayName("GET /api/movies/{id} — getMovieById")
    class GetMovieByIdTests {

        @Test
        @DisplayName("Should return 401 when no JWT is provided")
        void shouldReturn401WhenNoJwt() throws Exception {
            mockMvc.perform(get("/api/movies/1"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Should return movie with id=1 (Inception)")
        void shouldReturnMovieById() throws Exception {
            mockMvc.perform(get("/api/movies/1").with(mockJwt()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(1))
                    .andExpect(jsonPath("$.title").value("Inception"))
                    .andExpect(jsonPath("$.director").value("Christopher Nolan"));
        }

        @Test
        @DisplayName("Should return 404 for non-existent movie id")
        void shouldReturn404ForUnknownId() throws Exception {
            mockMvc.perform(get("/api/movies/999").with(mockJwt()))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("Should return Hindi movie (id=4: 3 Idiots)")
        void shouldReturnHindiMovie() throws Exception {
            mockMvc.perform(get("/api/movies/4").with(mockJwt()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.title").value("3 Idiots"))
                    .andExpect(jsonPath("$.language").value("Hindi"));
        }
    }

    @Nested
    @DisplayName("GET /api/movies/genre/{genre} — getMoviesByGenre")
    class GetMoviesByGenreTests {

        @Test
        @DisplayName("Should return Sci-Fi movies")
        void shouldReturnSciFiMovies() throws Exception {
            mockMvc.perform(get("/api/movies/genre/Sci-Fi").with(mockJwt()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.genre").value("Sci-Fi"))
                    .andExpect(jsonPath("$.count").value(3)) // Inception, Interstellar, Matrix
                    .andExpect(jsonPath("$.movies").isArray());
        }

        @Test
        @DisplayName("Should return Hindi language movies")
        void shouldReturnHindiMovies() throws Exception {
            mockMvc.perform(get("/api/movies/genre/Hindi").with(mockJwt()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.count").value(4)); // 3 Idiots, Dangal, DDLJ, Lagaan
        }

        @Test
        @DisplayName("Should return empty list for unknown genre")
        void shouldReturnEmptyForUnknownGenre() throws Exception {
            mockMvc.perform(get("/api/movies/genre/Unknown").with(mockJwt()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.count").value(0));
        }
    }
}
