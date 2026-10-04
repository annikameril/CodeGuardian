package com.codeguardian;

import java.io.IOException;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;

public class RepositoryScanner {

    public List<Path> findJavaFiles(String repositoryPath) throws IOException {

        List<Path> javaFiles = new ArrayList<>();

        Path repo = Paths.get(repositoryPath);

        if (!Files.exists(repo)) {
            throw new IllegalArgumentException(
                    "Repository path does not exist: " + repositoryPath
            );
        }

        Files.walk(repo)
                .filter(Files::isRegularFile)
                .filter(path -> path.toString().endsWith(".java"))
                .forEach(javaFiles::add);

        return javaFiles;
    }
}