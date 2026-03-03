package com.poc.resourceserver.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Movie domain model.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Movie {

    private Long id;
    private String title;
    private String genre;
    private int releaseYear;
    private double imdbRating;
    private String director;
    private String description;
    private String language;
}
