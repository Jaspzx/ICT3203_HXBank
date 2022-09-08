$(document).ready(function() {
    $.ajax({
        url: '/api/barchart_graph',
        type: 'GET',
    })
    .done(function(data, textStatus, xhr){
        if (xhr.status === 200) {
            drawChart(data.money_in, data.money_out);
        }
    })
    $("#refresh_balance").click(function() {
        let acc_balance = document.getElementById("acc_balance");
        let acc_remain = document.getElementById("acc_remain");
        let acc_limit = document.getElementById("acc_limit");
        $.ajax({
            url: '/api/acc_overview',
            type: 'GET',
        })
        .done(function(data, textStatus, xhr){
            if (xhr.status === 200) {
                acc_balance.textContent = "Total Balance: $" + data.acc_balance;
                acc_remain.textContent = "Daily Transfer Remaining: $" + (data.acc_xfer_limit - data.acc_xfer_daily);
                acc_limit.textContent = "Daily Transfer Limit: $" + data.acc_xfer_limit;
            }
        })
    })
    $("#refresh_chart").click(function() {
        $.ajax({
            url: '/api/barchart_graph',
            type: 'GET',
        })
        .done(function(data, textStatus, xhr){
            if (xhr.status === 200) {
                drawChart(data.money_in, data.money_out);
            }
        })
    })
})

function drawChart(moneyInStorage, moneyOutStorage) {
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
            plugins: {
                tooltip: {
                    callbacks: {
                        title: function(context) {
                            return toMonthName(context[0].label);
                        },
                    },
                },
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: "Months",
                    },
                    ticks: {
                        callback: function(value, index) {
                            return toMonthName(value + 1);
                        }
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
}

function toMonthName(monthNumber) {
    const date = new Date();
    date.setMonth(monthNumber - 1);

    return date.toLocaleString('en-US', {
        month: 'long',
    });
}