// demo data
console.log(new Date(2022, 0, 0))
console.log(new Date(2022, 8, 1))
moneyInStorage = [{x: new Date(2022, 0, 0), y: 100}, {x: new Date(2022, 8, 1), y: 1000}];
moneyOutStorage = [{x: new Date(2022, 0, 0), y: 100}, {x: new Date(2022, 8, 1), y: 1000}];

const chartHolderHTML = document.getElementById("graph");
const yearlyBarChartConfig = {
    type: "bar",
    data: {
        datasets: [
            {
                label: "Money In",
                data: moneyInStorage,
                borderColor: ["rgba(0, 0, 0, 1)"],
                backgroundColor: "Green",
            },
            {
                label: "Money Out",
                data: moneyOutStorage,
                borderColor: ["rgba(0, 0, 0, 1)"],
                backgroundColor: "Red",
            },
        ],
    },
    options: {
        responsive: true,
        maintainAspectRatio: true,
        scales: {
            x: {
                type: "time",
                title: {
                    display: false,
                    text: "Month",
                },
                time: {
                    unit: "month",
                    tooltipFormat: "MMM yyyy",
                },
                stacked: true,
            },
            y: {
                title: {
                    display: true,
                    text: "Amount ($)",
                },
                ticks: {
                    beginAtZero: true,
                },
                stacked: true,
            },
        },
    },
};
let yearlyBarChart = new Chart(chartHolderHTML, yearlyBarChartConfig);