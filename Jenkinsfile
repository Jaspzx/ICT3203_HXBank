pipeline {
    agent any
    stages {
        stage ('Checkout') {
            steps {
                git branch:'master', url: 'https://github.com/OWASP/Vulnerable-WebApplication.git'
            }
        }
        stage('Code Quality Check via SonarQube') {
            steps {
                script{
                    def scannerHome = tool 'SonarQube';
                    withSonarQubeEnv('SonarQube') {
                        sh "${scannerHome}/bin/sonar-scanner -Dsonar.projectKey=03HXBank -Dsonar.sources=."
                    }
                }
            }
        }
    }
    post {
        always {
            recordIssues enabledForFailure: true, tool: sonarQube()
        }
    }
}
