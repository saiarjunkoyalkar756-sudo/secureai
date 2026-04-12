$ExecutorKey = "sk_test_executor_789"
$BaseUrl = "http://localhost:3000/v1/execute"
$Headers = @{
    "Authorization" = "Bearer $ExecutorKey"
    "Content-Type"  = "application/json"
}

$TestCases = @(
    @{ name = "Hello World"; code = "print('Hello SecureAI')" },
    @{ name = "Loop 0-4"; code = "for i in range(5): print(i)" },
    @{ name = "Variables"; code = "x = 10`ny = 20`nprint(x + y)" },
    @{ name = "Math Import"; code = "import math`nprint(math.sqrt(144))" },
    @{ name = "String Concat"; code = "name='Vilas'`nprint('Hello ' + name)" },
    @{ name = "List Sum"; code = "numbers=[1,2,3,4,5]`nprint(sum(numbers))" },
    @{ name = "File Read Attack"; code = "print(open('test.txt').read())" },
    @{ name = "Infinite Loop DoS"; code = "while True:`n  pass" },
    @{ name = "Calculation Test"; code = "print('Current calculation test')`nprint(25 * 4)" },
    @{ name = "Squares Loop"; code = "for i in range(1,11):`n  print(f'Square of {i} = {i*i}')" },
    @{ name = "String Reverse"; code = "text='secureai'`nprint(text.upper())`nprint(text[::-1])" },
    @{ name = "Dictionary Info"; code = "data={'name':'Vilas','role':'Developer'}`nprint(data)" },
    @{ name = "List Sort"; code = "nums=[5,2,9,1]`nnums.sort()`nprint(nums)" },
    @{ name = "Zero Division"; code = "try:`n  print(10/0)`nexcept Exception as e:`n  print('Error:', e)" },
    @{ name = "Random Number"; code = "import random`nprint(random.randint(1,100))" },
    @{ name = "Function Greet"; code = "def greet(name):`n  return f'Hello {name}'`nprint(greet('SecureAI'))" },
    @{ name = "Directory Listing Attack"; code = "import os`nprint(os.listdir())" },
    @{ name = "Network Egress Attack"; code = "import requests`nprint(requests.get('https://google.com').status_code)" }
)

Write-Host "🚀 Starting SecureAI Sandbox Security Audit..." -ForegroundColor Cyan
Write-Host "-------------------------------------------"

foreach ($test in $TestCases) {
    Write-Host "Testing: $($test.name)..." -NoNewline
    $body = @{
        language = "python3.11"
        code     = $test.code
    } | ConvertTo-Json

    try {
        $response = Invoke-RestMethod -Uri $BaseUrl -Method Post -Headers $Headers -Body $body -ErrorAction Stop
        Write-Host " [Result: $($response.status)]" -ForegroundColor Green
        if ($response.output) {
            Write-Host " Output: $($response.output)" -ForegroundColor Gray
        }
        if ($response.error) {
            Write-Host " Error: $($response.error)" -ForegroundColor Red
        }
    } catch {
        Write-Host " [FAILED]" -ForegroundColor Red
        Write-Host " Status: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "-------------------------------------------"
Write-Host "✅ Audit Complete." -ForegroundColor Cyan
