$(document).ready(function() {
    $.ajax({
        url: '/api/barchart-graph',
        type: 'GET',
    })
    .done(function(data, textStatus, xhr){
        if (xhr.status === 200) {
            drawChart(data.money_in, data.money_out);
        }
    })
    $("#refresh_balance").click(function() {
        let acc_balance = document.getElementById("acc_balance");
        let balance_on_hold = document.getElementById("balance_on_hold");
        let acc_remain = document.getElementById("acc_remain");
        let acc_limit = document.getElementById("acc_limit");
        $.ajax({
            url: '/api/acc-overview',
            type: 'GET',
        })
        .done(function(data, textStatus, xhr){
            if (xhr.status === 200) {
                acc_balance.textContent = "Total Balance: $" + data.acc_balance;
                balance_on_hold.textContent = "Total Available Balance: $" + data.acc_balance_on_hold;
                acc_remain.textContent = "Daily Transfer Remaining: $" + data.acc_xfer_daily;
                acc_limit.textContent = "Daily Transfer Limit: $" + data.acc_xfer_limit;
            }
        })
    })
    $("#refresh_chart").click(function() {
        $.ajax({
            url: '/api/barchart-graph',
            type: 'GET',
        })
        .done(function(data, textStatus, xhr){
            if (xhr.status === 200) {
                destroyChart();
                drawChart(data.money_in, data.money_out);
            }
        })
    })
    $("#refresh_transactions").click(function() {
        let table_body = document.getElementById("recentTransactionTableBody");
        $.ajax({
            url: '/api/recent-transactions',
            type: 'GET',
        })
        .done(function(data, textStatus, xhr){
            if (xhr.status === 200) {
                if (table_body.rows.length !== 0) {
                    while(table_body.hasChildNodes()) {
                        table_body.removeChild(table_body.firstChild);
                    }
                }
                for (const [key, value] of Object.entries(data)) {
                    var row = table_body.insertRow(0);
                    var date = row.insertCell(0);
                    date.textContent = value.date_transferred;
                    var recipient = row.insertCell(1);
                    recipient.textContent = value.transferee_acc;
                    var desc = row.insertCell(2);
                    desc.textContent = value.description;
                    var amt = row.insertCell(3);
                    amt.textContent = "$" + value.amt_transferred;
                    var status = row.insertCell(4);
                    if (value.status === 0) {
                        status.textContent = "Approved";
                    } else if (value.status === 1) {
                        status.textContent = "Pending Approval";
                    } else {
                        status.textContent = "Rejected";
                    }
                }
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

function destroyChart() {
    let chartStatus = Chart.getChart("graph");
    if (chartStatus != undefined) {
        chartStatus.destroy();
    }
}

function toMonthName(monthNumber) {
    const date = new Date();
    date.setMonth(monthNumber - 1);

    return date.toLocaleString('en-US', {
        month: 'long',
    });
}