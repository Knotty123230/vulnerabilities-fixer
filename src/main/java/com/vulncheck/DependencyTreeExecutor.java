package com.vulncheck;

import java.nio.file.Path;

public interface DependencyTreeExecutor {

    public Path execute(Path fileWithDeps);

}
