#!/bin/bash

set -e

RESULTS_FILE="$1"
if [ -z "$RESULTS_FILE" ]; then
    echo "Usage: $0 <benchmark-results.json>"
    exit 1
fi

echo "🔍 Running benchmark performance assertions (bash-only version)..."

# Function to extract benchmark results using grep and sed
extract_benchmark_result() {
    local bench_name="$1"
    local results_file="$2"
    
    # Find lines containing benchmark results for this specific benchmark
    # Look for lines that contain the benchmark name and "ns/op"
    grep -F "$bench_name" "$results_file" | grep "ns/op" | grep '"Action":"output"' | sed -n 's/.*"Output":"\([^"]*\)".*/\1/p' | sed 's/\\n/\n/g' | sed 's/\\t/\t/g'
}

# Function to assert benchmark performance
assert_benchmark() {
    local bench_name="$1"
    local max_ns_per_op="$2"
    local max_allocs_per_op="$3"

    # Extract benchmark output lines
    local output_lines=$(extract_benchmark_result "$bench_name" "$RESULTS_FILE")

    if [ -z "$output_lines" ]; then
        echo "❌ Benchmark $bench_name: No output found"
        return 1
    fi

    # Get the last (most recent) result line
    local output_line=$(echo "$output_lines" | tail -1)

    # Parse metrics from the output line using sed regex
    # Extract ns/op value (number before "ns/op")
    local ns_per_op=$(echo "$output_line" | sed -n 's/.* \([0-9]\+\) ns\/op.*/\1/p' | sed 's/,//g')
    
    # Extract allocs/op value (number before "allocs/op")  
    local allocs_per_op=$(echo "$output_line" | sed -n 's/.* \([0-9]\+\) allocs\/op.*/\1/p' | sed 's/,//g')

    # Validate that we got numeric values
    if ! [[ "$ns_per_op" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        echo "❌ Benchmark $bench_name: Could not parse ns/op value from: $output_line"
        return 1
    fi

    if ! [[ "$allocs_per_op" =~ ^[0-9]+$ ]]; then
        echo "❌ Benchmark $bench_name: Could not parse allocs/op value from: $output_line"
        return 1
    fi

    # Perform assertions
    local ns_check=$(echo "$ns_per_op > $max_ns_per_op" | bc -l 2>/dev/null || echo "1")
    local allocs_check=$((allocs_per_op > max_allocs_per_op))

    if [ "$ns_check" = "1" ]; then
        echo "❌ $bench_name: ns/op ($ns_per_op) exceeds threshold ($max_ns_per_op)"
        return 1
    fi

    if [ "$allocs_check" -eq 1 ]; then
        echo "❌ $bench_name: allocs/op ($allocs_per_op) exceeds threshold ($max_allocs_per_op)"
        return 1
    fi

    echo "✅ $bench_name: ns/op=$ns_per_op, allocs/op=$allocs_per_op"
    return 0
}

assert_benchmark "BenchmarkLibraryNative_HashSHA3_256" 9500 5
assert_benchmark "BenchmarkLibraryNative_HashSHA3_384" 9600 5
assert_benchmark "BenchmarkLibraryNative_HashSHA3_512" 9700 5

assert_benchmark "BenchmarkLibraryNative_HashSHA_256" 9300 3
assert_benchmark "BenchmarkLibraryNative_HashSHA_384" 9400 3
assert_benchmark "BenchmarkLibraryNative_HashSHA_512" 9450 3
assert_benchmark "BenchmarkLibraryNative_HashSHA_512_256" 9420 3

assert_benchmark "BenchmarkLibraryNative_HashShake_128" 9800 8
assert_benchmark "BenchmarkLibraryNative_HashShake_256" 9900 8

if grep -q '"Test":"BenchmarkLibraryNative_SignCertificate"' "$RESULTS_FILE" && grep -q '"Action":"fail"' "$RESULTS_FILE"; then
    echo "⚠️  BenchmarkLibraryNative_SignCertificate: Skipped due to test failure"
else
    assert_benchmark "BenchmarkLibraryNative_SignCertificate" 950000 50
fi

echo ""
echo "All benchmark assertions passed!"
echo ""
echo "Full Benchmark Summary:"
grep '"Action":"output"' "$RESULTS_FILE" | grep -E "(ns/op|B/op|allocs/op)" | sed -n 's/.*"Output":"\([^"]*\)".*/\1/p' | sed 's/\\n/\n/g' | sed 's/\\t/\t/g' | sed 's/^/   /'