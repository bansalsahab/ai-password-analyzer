/**
 * Charts.js - Enhanced Attack vector visualization for password analyzer
 * With advanced visualizations and interactive elements
 */

// Initialize chart objects
let attackChart = null;
let securityRadarChart = null;
let timeEvolutionChart = null;
let passwordDnaChart = null;

// Store all charts in a global object for easy reference
window.passwordCharts = {
    attackChart: null,
    securityRadarChart: null,
    timeEvolutionChart: null,
    passwordDnaChart: null
};

// Set Chart.js global defaults - these will be updated dynamically based on theme
function updateChartDefaults(isDarkMode) {
    Chart.defaults.color = isDarkMode ? '#ffffff' : '#333333';
    Chart.defaults.borderColor = isDarkMode ? '#333333' : '#e2e2e2';
    Chart.defaults.font.family = "'Poppins', sans-serif";
}

// Initial setup with current theme
updateChartDefaults(document.body.classList.contains('light-mode') === false);

// Gradient creator helper
function createGradient(ctx, startColor, endColor) {
    const gradient = ctx.createLinearGradient(0, 0, 0, 400);
    gradient.addColorStop(0, startColor);
    gradient.addColorStop(1, endColor);
    return gradient;
}

// Get theme-appropriate grid color
function getGridColor(isDarkMode) {
    return isDarkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
}

// Function to initialize all charts
function initializeCharts() {
    console.log('Initializing charts...');
    // Will be called once DOM is loaded - initialize empty charts
    const attackCtx = document.getElementById('attackChart').getContext('2d');
    const radarCtx = document.getElementById('securityRadarChart').getContext('2d');
    const timelineCtx = document.getElementById('timeEvolutionChart').getContext('2d');
    const dnaCtx = document.getElementById('passwordDnaChart').getContext('2d');
    
    // Determine if we're in dark mode
    const isDarkMode = document.body.classList.contains('light-mode') === false;
    
    // Create gradients
    const vulnerabilityGradient = createGradient(attackCtx, 'rgba(255, 99, 132, 0.8)', 'rgba(255, 99, 132, 0.1)');
    const charTypesGradient = createGradient(attackCtx, 'rgba(54, 162, 235, 0.8)', 'rgba(54, 162, 235, 0.1)');

    // Initialize empty attack vector chart
    attackChart = new Chart(attackCtx, {
        type: 'bar',
        data: {
            labels: ['Dictionary', 'Brute Force', 'Pattern-Based', 'Targeted Guess', 'Leaked Database'],
            datasets: [{
                label: 'Vulnerability Level (%)',
                data: [0, 0, 0, 0, 0],
                backgroundColor: vulnerabilityGradient,
                borderColor: 'rgba(255, 99, 132, 1)',
                borderWidth: 1,
                borderRadius: 4,
                barPercentage: 0.6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                duration: 1500,
                easing: 'easeOutQuart'
            },
            plugins: {
                legend: {
                    display: true,
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'PASSWORD VULNERABILITY ANALYSIS',
                    font: {
                        size: 16,
                        weight: 'bold'
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `${context.dataset.label}: ${context.raw.toFixed(1)}%`;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    title: {
                        display: true,
                        text: 'VULNERABILITY LEVEL (%)'
                    },
                    grid: {
                        color: getGridColor(isDarkMode)
                    }
                },
                x: {
                    grid: {
                        display: false
                    }
                }
            }
        }
    });
    
    // Initialize empty security radar chart
    securityRadarChart = new Chart(radarCtx, {
        type: 'radar',
        data: {
            labels: ['Complexity', 'Uniqueness', 'Length', 'Char Diversity', 'Unpredictability', 'Memorability'],
            datasets: [{
                label: 'Your Password',
                data: [0, 0, 0, 0, 0, 0],
                backgroundColor: 'rgba(255, 99, 132, 0.2)',
                borderColor: 'rgba(255, 99, 132, 1)',
                borderWidth: 2,
                pointBackgroundColor: 'rgba(255, 99, 132, 1)',
                pointRadius: 4
            }, {
                label: 'Ideal Password',
                data: [100, 100, 100, 100, 100, 80],
                backgroundColor: 'rgba(54, 162, 235, 0.1)',
                borderColor: 'rgba(54, 162, 235, 0.8)',
                borderWidth: 1,
                borderDash: [5, 5],
                pointBackgroundColor: 'rgba(54, 162, 235, 0.8)',
                pointRadius: 3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'PASSWORD SECURITY PROFILE',
                    font: {
                        size: 16,
                        weight: 'bold'
                    }
                }
            },
            scales: {
                r: {
                    angleLines: {
                        color: isDarkMode ? 'rgba(255, 255, 255, 0.15)' : 'rgba(0, 0, 0, 0.15)'
                    },
                    grid: {
                        color: getGridColor(isDarkMode)
                    },
                    pointLabels: {
                        font: {
                            size: 12
                        }
                    },
                    ticks: {
                        backdropColor: 'transparent',
                        showLabelBackdrop: false,
                        maxTicksLimit: 5,
                        display: false
                    },
                    suggestedMin: 0,
                    suggestedMax: 100
                }
            },
            animation: {
                duration: 2000,
                easing: 'easeOutQuart'
            }
        }
    });
    
    // Initialize empty time evolution chart
    timeEvolutionChart = new Chart(timelineCtx, {
        type: 'line',
        data: {
            labels: ['Now', '1 Year', '3 Years', '5 Years', '10 Years'],
            datasets: [{
                label: 'Security Strength Over Time',
                data: [100, 0, 0, 0, 0],
                borderColor: 'rgba(75, 192, 192, 1)',
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                fill: true,
                tension: 0.3,
                pointBackgroundColor: 'rgba(75, 192, 192, 1)',
                pointBorderColor: '#fff',
                pointHoverBackgroundColor: '#fff',
                pointHoverBorderColor: 'rgba(75, 192, 192, 1)',
                pointRadius: 5,
                pointHoverRadius: 7
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: 'PASSWORD SECURITY OVER TIME',
                    font: {
                        size: 16,
                        weight: 'bold'
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `Security: ${context.raw}%`;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    title: {
                        display: true,
                        text: 'SECURITY STRENGTH (%)'
                    },
                    grid: {
                        color: getGridColor(isDarkMode)
                    }
                },
                x: {
                    grid: {
                        display: false
                    }
                }
            }
        }
    });
    
    // Initialize DNA visualization chart
    passwordDnaChart = new Chart(dnaCtx, {
        type: 'doughnut',
        data: {
            labels: ['Lowercase', 'Uppercase', 'Digits', 'Special Chars'],
            datasets: [{
                data: [25, 25, 25, 25],
                backgroundColor: [
                    'rgba(54, 162, 235, 0.8)',
                    'rgba(255, 99, 132, 0.8)',
                    'rgba(255, 206, 86, 0.8)',
                    'rgba(75, 192, 192, 0.8)'
                ],
                borderColor: [
                    'rgba(54, 162, 235, 1)',
                    'rgba(255, 99, 132, 1)',
                    'rgba(255, 206, 86, 1)',
                    'rgba(75, 192, 192, 1)'
                ],
                borderWidth: 1,
                cutout: '70%',
                hoverOffset: 15
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        boxWidth: 12,
                        padding: 15
                    }
                },
                title: {
                    display: true,
                    text: 'CHARACTER COMPOSITION',
                    font: {
                        size: 16,
                        weight: 'bold'
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `${context.label}: ${context.raw.toFixed(1)}%`;
                        }
                    }
                }
            },
            animation: {
                animateRotate: true,
                animateScale: true,
                duration: 2000,
                easing: 'easeOutQuart'
            }
        }
    });
    
    // Store charts in the global object for theme toggle access
    window.passwordCharts = {
        attackChart,
        securityRadarChart,
        timeEvolutionChart,
        passwordDnaChart
    };
}

// Function to update the attack vector chart with password analysis data
function updateCharts(patternData) {
    console.log('Updating charts with data:', patternData);
    
    // Update attack vector data
    const attackVectors = patternData.attack_vectors;
    attackChart.data.datasets[0].data = [
        attackVectors.dictionary,
        attackVectors.brute_force,
        attackVectors.pattern_based,
        attackVectors.targeted_guess,
        attackVectors.leaked_database
    ];
    attackChart.update();
    
    // Update character types distribution
    const charTypes = patternData.char_types;
    passwordDnaChart.data.datasets[0].data = [
        charTypes.lowercase,
        charTypes.uppercase,
        charTypes.digits,
        charTypes.special
    ];
    passwordDnaChart.update();
    
    // Calculate overall security score metrics
    const overallScore = 100 - (
        attackVectors.dictionary * 0.2 + 
        attackVectors.brute_force * 0.2 + 
        attackVectors.pattern_based * 0.2 + 
        attackVectors.targeted_guess * 0.2 + 
        attackVectors.leaked_database * 0.2
    );
    
    // Calculate individual security metrics
    let lengthScore = Math.min(100, Math.sqrt(patternData.password_length) * 20);
    let complexityScore = overallScore;
    let uniquenessScore = attackVectors.leaked_database > 50 ? 0 : 100 - attackVectors.leaked_database;
    let charDiversityScore = (
        (charTypes.lowercase > 0 ? 25 : 0) + 
        (charTypes.uppercase > 0 ? 25 : 0) + 
        (charTypes.digits > 0 ? 25 : 0) + 
        (charTypes.special > 0 ? 25 : 0)
    );
    let unpredictabilityScore = 100 - attackVectors.pattern_based;
    
    // Memorability is inversely related to some aspects of security
    // Complex random passwords are harder to remember
    let memorabilityScore = Math.max(20, 100 - (
        (charDiversityScore * 0.3) + 
        (lengthScore * 0.4) + 
        (unpredictabilityScore * 0.3)
    ) * 0.6);
    
    // Update radar chart data
    securityRadarChart.data.datasets[0].data = [
        complexityScore,
        uniquenessScore,
        lengthScore,
        charDiversityScore,
        unpredictabilityScore,
        memorabilityScore
    ];
    securityRadarChart.update();
    
    // Calculate security degradation over time
    // Based on Moore's Law (computing power doubles every ~18 months)
    // This means cracking time is cut in half every 18 months
    const degradationFactors = [
        1.0,                // Now
        0.65,               // 1 year
        0.35,               // 3 years
        0.15,               // 5 years
        0.05                // 10 years (with quantum computing potential)
    ];
    
    // Calculate future security scores
    const futureScores = degradationFactors.map(factor => 
        Math.max(0, Math.min(100, overallScore * factor))
    );
    
    // Update time evolution chart
    timeEvolutionChart.data.datasets[0].data = futureScores;
    timeEvolutionChart.update();
}

// Function to update chart theme colors based on current theme
function updateChartsTheme() {
    const isDarkMode = document.body.classList.contains('light-mode') === false;
    
    // Update Chart.js global defaults
    updateChartDefaults(isDarkMode);
    
    // Update grid colors for each chart
    if (window.passwordCharts.attackChart) {
        window.passwordCharts.attackChart.options.scales.y.grid.color = getGridColor(isDarkMode);
        window.passwordCharts.attackChart.update();
    }
    
    if (window.passwordCharts.timeEvolutionChart) {
        window.passwordCharts.timeEvolutionChart.options.scales.y.grid.color = getGridColor(isDarkMode);
        window.passwordCharts.timeEvolutionChart.update();
    }
    
    if (window.passwordCharts.securityRadarChart) {
        window.passwordCharts.securityRadarChart.options.scales.r.angleLines.color = 
            isDarkMode ? 'rgba(255, 255, 255, 0.15)' : 'rgba(0, 0, 0, 0.15)';
        window.passwordCharts.securityRadarChart.options.scales.r.grid.color = getGridColor(isDarkMode);
        window.passwordCharts.securityRadarChart.update();
    }
}

// Listen for theme changes
document.addEventListener('themeChanged', function() {
    updateChartsTheme();
});

// Wait for DOM to be ready
document.addEventListener('DOMContentLoaded', function() {
    try {
        initializeCharts();
        console.log('Charts initialized successfully');
        
        // Set up theme toggle listener
        const themeToggle = document.getElementById('themeToggle');
        if (themeToggle) {
            themeToggle.addEventListener('change', function() {
                // Dispatch a custom event that our charts can listen for
                document.dispatchEvent(new CustomEvent('themeChanged'));
            });
        }
    } catch (error) {
        console.error('Error initializing charts:', error);
    }
}); 