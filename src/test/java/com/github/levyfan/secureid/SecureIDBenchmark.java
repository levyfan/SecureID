package com.github.levyfan.secureid;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@State(Scope.Benchmark)
public class SecureIDBenchmark {

    private SecretKey sk;

    @Setup
    public void setUp() {
        sk = SecretKey.generate();
    }

    @TearDown
    public void tearDown() {
        sk.close();
    }

    @Benchmark
    public void bmSign1() {
        sk.sign1("hello world".getBytes());
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(SecureIDBenchmark.class.getSimpleName())
                .forks(1)
                .build();
        new Runner(opt).run();
    }
}
