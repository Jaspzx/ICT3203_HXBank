pipeline {
    agent any
    stages {
        stage ('Checkout') {
            steps {
                git branch:'main', url: 'https://github.com/ryangohsc/ICT3203_HXBank'
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
