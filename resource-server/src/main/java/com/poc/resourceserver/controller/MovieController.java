package com.poc.resourceserver.controller;

import com.poc.resourceserver.model.Movie;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Movie Controller — Protected Resource.
 *
 * ALL endpoints require a valid JWT Bearer token.
 * JWT is issued by auth-server (http://localhost:9000/oauth2/token)
 * and verified using auth-server's public keys from /.well-known/jwks.json.
 *
 * Required scope: movies:read
 *
 * ┌──────────────────────────────────────────────────────────────────┐
 * │  PROTECTED — JWT Bearer token required (validated via JWKS)      │
 * │                                                                  │
 * │  GET /api/movies             → provideMovieDetails (all movies)  │
 * │  GET /api/movies/{id}        → single movie by ID                │
 * │  GET /api/movies/genre/{g}   → movies filtered by genre          │
 * └──────────────────────────────────────────────────────────────────┘
 */
@Slf4j
@RestController
@RequestMapping("/api/movies")
public class MovieController {

    /** Static in-memory movie catalogue — represents the protected resource */
    private static final List<Movie> MOVIE_CATALOGUE = List.of(
        Movie.builder().id(1L).title("Inception").genre("Sci-Fi").releaseYear(2010)
            .imdbRating(8.8).director("Christopher Nolan")
            .description("A thief who enters people's dreams to steal secrets.")
            .language("English").build(),

        Movie.builder().id(2L).title("The Dark Knight").genre("Action").releaseYear(2008)
            .imdbRating(9.0).director("Christopher Nolan")
            .description("Batman faces the Joker, a criminal mastermind in Gotham City.")
            .language("English").build(),

        Movie.builder().id(3L).title("Interstellar").genre("Sci-Fi").releaseYear(2014)
            .imdbRating(8.6).director("Christopher Nolan")
            .description("Astronauts travel through a wormhole near Saturn.")
            .language("English").build(),

        Movie.builder().id(4L).title("3 Idiots").genre("Comedy-Drama").releaseYear(2009)
            .imdbRating(8.4).director("Rajkumar Hirani")
            .description("Three engineering students chase dreams against societal pressure.")
            .language("Hindi").build(),

        Movie.builder().id(5L).title("Dangal").genre("Biography").releaseYear(2016)
            .imdbRating(8.4).director("Nitesh Tiwari")
            .description("A former wrestler trains his daughters to become world-class wrestlers.")
            .language("Hindi").build(),

        Movie.builder().id(6L).title("The Shawshank Redemption").genre("Drama").releaseYear(1994)
            .imdbRating(9.3).director("Frank Darabont")
            .description("A banker is sentenced to life in Shawshank State Penitentiary.")
            .language("English").build(),

        Movie.builder().id(7L).title("Avengers: Endgame").genre("Action").releaseYear(2019)
            .imdbRating(8.4).director("Russo Brothers")
            .description("The Avengers assemble once more to reverse Thanos' actions.")
            .language("English").build(),

        Movie.builder().id(8L).title("Dilwale Dulhania Le Jayenge").genre("Romance").releaseYear(1995)
            .imdbRating(8.1).director("Aditya Chopra")
            .description("Two Indians meet in Europe and fall in love.")
            .language("Hindi").build(),

        Movie.builder().id(9L).title("The Matrix").genre("Sci-Fi").releaseYear(1999)
            .imdbRating(8.7).director("Wachowski Sisters")
            .description("A hacker discovers the true nature of reality.")
            .language("English").build(),

        Movie.builder().id(10L).title("Lagaan").genre("Drama").releaseYear(2001)
            .imdbRating(8.1).director("Ashutosh Gowariker")
            .description("Villagers challenge British officers to a game of cricket.")
            .language("Hindi").build()
    );

    /**
     * Provide all movie details — the main protected endpoint.
     *
     * Requires: Authorization: Bearer <JWT from auth-server>
     * JWT must have scope: movies:read
     *
     * @param jwt  Injected by Spring Security after successful JWT validation
     * @return List of all 10 movies in the catalogue
     */
    @GetMapping
    public ResponseEntity<Map<String, Object>> provideMovieDetails(
            @AuthenticationPrincipal Jwt jwt) {

        log.info("Movie catalogue requested by client=[{}] scope=[{}] kid=[{}]",
                jwt.getSubject(),
                jwt.getClaimAsString("scope"),
                jwt.getHeaders().get("kid"));

        return ResponseEntity.ok(Map.of(
                "requestedBy",  jwt.getSubject(),
                "scope",        jwt.getClaimAsString("scope"),
                "issuedBy",     jwt.getIssuer(),
                "tokenKid",     jwt.getHeaders().getOrDefault("kid", "unknown"),
                "totalMovies",  MOVIE_CATALOGUE.size(),
                "movies",       MOVIE_CATALOGUE
        ));
    }

    /**
     * Get a single movie by ID.
     *
     * @param id  Movie ID (1–10)
     * @param jwt Authenticated JWT principal
     */
    @GetMapping("/{id}")
    public ResponseEntity<?> getMovieById(
            @PathVariable Long id,
            @AuthenticationPrincipal Jwt jwt) {

        log.info("Movie [id={}] requested by client=[{}]", id, jwt.getSubject());

        Optional<Movie> movie = MOVIE_CATALOGUE.stream()
                .filter(m -> m.getId().equals(id))
                .findFirst();

        return movie
                .<ResponseEntity<?>>map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * Get movies filtered by genre.
     *
     * @param genre  Genre name (e.g. "Sci-Fi", "Action", "Hindi")
     * @param jwt    Authenticated JWT principal
     */
    @GetMapping("/genre/{genre}")
    public ResponseEntity<Map<String, Object>> getMoviesByGenre(
            @PathVariable String genre,
            @AuthenticationPrincipal Jwt jwt) {

        log.info("Movies by genre=[{}] requested by client=[{}]", genre, jwt.getSubject());

        List<Movie> filtered = MOVIE_CATALOGUE.stream()
                .filter(m -> m.getGenre().equalsIgnoreCase(genre)
                          || m.getLanguage().equalsIgnoreCase(genre))
                .toList();

        return ResponseEntity.ok(Map.of(
                "genre",   genre,
                "count",   filtered.size(),
                "movies",  filtered
        ));
    }
}
