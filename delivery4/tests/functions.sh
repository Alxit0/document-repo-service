function run_test() {
    command="$1"
    expected_code="$2"

    # Run the command and capture the exit code
    eval "$command" > ./out 2>&1
    actual_code=$?

    # Compare the actual exit code to the expected exit code
    if [[ $actual_code -eq $expected_code ]]; then
        echo "  Test passed"
    else
        # Re-run the command without ignoring output for debugging
        echo "  Test failed: '$command' returned $actual_code, but expected $expected_code."
        cat ./out
    fi
}