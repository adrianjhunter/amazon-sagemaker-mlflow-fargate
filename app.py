# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from aws_cdk import (
    aws_ec2 as ec2,
    aws_s3 as s3,
    aws_ecs as ecs,
    aws_elasticloadbalancingv2 as elbv2,
    aws_rds as rds,
    aws_iam as iam,
    aws_secretsmanager as sm,
    aws_ecs_patterns as ecs_patterns,
    aws_route53 as route53,
    aws_route53_targets as targets,
    aws_certificatemanager as acm,
    core
)


class DeploymentStack(core.Stack):
    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)
        # ==============================
        # ======= CFN PARAMETERS =======
        # ==============================
        project_name_param = core.CfnParameter(scope=self, id='ProjectName', type='String')
        db_name = 'mlflowdb'
        port = 3306
        username = 'master'
        bucket_name = f'{project_name_param.value_as_string}-artifacts-{core.Aws.ACCOUNT_ID}'
        container_repo_name = 'mlflow-containers'
        cluster_name = 'mlflow'
        service_name = 'mlflow'
        hosted_zone_id = 'Z1234ABCD5EFGH'
        hosted_zone_name = 'example.com'
        client_id = 'a1b2c3d4e5f6g7h8i9j0k'
        client_secret = core.SecretValue.secrets_manager('okta_client_secret')
        authorization_server = 'https://dev-12345678.okta.com'

        # ==================================================
        # ================= IAM ROLE =======================
        # ==================================================
        role = iam.Role(scope=self, id='TASKROLE', assumed_by=iam.ServicePrincipal(service='ecs-tasks.amazonaws.com'))
        role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name('AmazonS3FullAccess'))
        role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name('AmazonECS_FullAccess'))

        # ==================================================
        # ================== SECRET ========================
        # ==================================================
        db_password_secret = sm.Secret(
            scope=self,
            id='DBSECRET',
            secret_name='dbPassword',
            generate_secret_string=sm.SecretStringGenerator(password_length=20, exclude_punctuation=True)
        )

        # ==================================================
        # ==================== VPC =========================
        # ==================================================
        public_subnet = ec2.SubnetConfiguration(name='Public', subnet_type=ec2.SubnetType.PUBLIC, cidr_mask=28)
        private_subnet = ec2.SubnetConfiguration(name='Private', subnet_type=ec2.SubnetType.PRIVATE, cidr_mask=28)
        isolated_subnet = ec2.SubnetConfiguration(name='DB', subnet_type=ec2.SubnetType.ISOLATED, cidr_mask=28)

        vpc = ec2.Vpc(
            scope=self,
            id='VPC',
            cidr='10.0.0.0/24',
            max_azs=2,
            nat_gateway_provider=ec2.NatProvider.gateway(),
            nat_gateways=1,
            subnet_configuration=[public_subnet, private_subnet, isolated_subnet]
        )
        vpc.add_gateway_endpoint('S3Endpoint', service=ec2.GatewayVpcEndpointAwsService.S3)
        # ==================================================
        # ================= S3 BUCKET ======================
        # ==================================================
        artifact_bucket = s3.Bucket(
            scope=self,
            id='ARTIFACTBUCKET',
            bucket_name=bucket_name,
            public_read_access=False,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=core.RemovalPolicy.DESTROY
        )
        # # ==================================================
        # # ================== DATABASE  =====================
        # # ==================================================
        # Creates a security group for AWS RDS
        sg_rds = ec2.SecurityGroup(scope=self, id='SGRDS', vpc=vpc, security_group_name='sg_rds')
        # Adds an ingress rule which allows resources in the VPC's CIDR to access the database.
        #sg_rds.add_ingress_rule(peer=ec2.Peer.ipv4('10.0.0.0/24'), connection=ec2.Port.tcp(port))

        database = rds.DatabaseInstance(
            scope=self,
            id='MYSQL',
            database_name=db_name,
            port=port,
            credentials=rds.Credentials.from_username(username=username, password=db_password_secret.secret_value),
            engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_19),
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.SMALL),
            vpc=vpc,
            security_groups=[sg_rds],
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.ISOLATED),
            # multi_az=True,
            removal_policy=core.RemovalPolicy.DESTROY,
            deletion_protection=False
        )
        # ==================================================
        # =============== FARGATE SERVICE ==================
        # ==================================================
        cluster = ecs.Cluster(scope=self, id='CLUSTER', cluster_name=cluster_name, vpc=vpc)

        task_definition = ecs.FargateTaskDefinition(
            scope=self,
            id='MLflow',
            task_role=role,

        )

        container = task_definition.add_container(
            id='Container',
            image=ecs.ContainerImage.from_asset(
                directory='container',
                repository_name=container_repo_name
            ),
            environment={
                'BUCKET': f's3://{artifact_bucket.bucket_name}',
                'HOST': database.db_instance_endpoint_address,
                'PORT': str(port),
                'DATABASE': db_name,
                'USERNAME': username
            },
            secrets={
                'PASSWORD': ecs.Secret.from_secrets_manager(db_password_secret)
            }
        )
        port_mapping = ecs.PortMapping(container_port=5000, host_port=5000, protocol=ecs.Protocol.TCP)
        container.add_port_mappings(port_mapping)

        # ==================================================
        # ================ CERTIFICATE =====================
        # ==================================================
        zone = route53.HostedZone.from_hosted_zone_attributes(self, "HostedZone",
            hosted_zone_id = hosted_zone_id,
            zone_name = hosted_zone_name
        )
        
        certificate = acm.Certificate(self, "Certificate",
            domain_name="mlflow." + hosted_zone_name,
            validation=acm.CertificateValidation.from_dns(zone)
        )

        # ==================================================
        # =============== LOAD BALANCER ====================
        # ==================================================
        lb = elbv2.ApplicationLoadBalancer(scope=self, id="LB",
            vpc=vpc,
            internet_facing=True
        )
        # redirect HTTP requests to HTTPS
        lb.add_redirect()
        # allow Load Balancer to verify OIDC tokens with IDP
        lb.connections.allow_to_any_ipv4(ec2.Port.tcp(443),"allow ALB to verify token")

        listener = lb.add_listener("Listener",
            port=443,
            certificates=[certificate],
            ssl_policy=elbv2.SslPolicy.TLS12 # May want to confirm your SSL Policy preference https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html#describe-ssl-policies
        )

        target_group = elbv2.ApplicationTargetGroup(
            scope=self,
            id="TG",
            vpc=vpc,
            port=80,
            target_type=elbv2.TargetType.IP
        )

        target_group.configure_health_check(
            healthy_threshold_count=5
        )

        listener.add_action("DefaultAction",
            action=elbv2.ListenerAction.authenticate_oidc(
                authorization_endpoint=authorization_server + "/oauth2/default/v1/authorize",
                client_id=client_id,
                client_secret=client_secret,
                issuer=authorization_server + "/oauth2/default",
                token_endpoint=authorization_server + "/oauth2/default/v1/token",
                user_info_endpoint=authorization_server + "/oauth2/default/v1/userinfo",
                scope="openid profile",
                session_timeout=core.Duration.seconds(300),
                next=elbv2.ListenerAction.forward([target_group])
            )
        )
        
        route53.ARecord(
            scope=self,
            id="AliasRecord",
            zone=zone,
            record_name="mlflow",
            target=route53.RecordTarget.from_alias(targets.LoadBalancerTarget(lb))
        )

        fargate_service = ecs.FargateService(
           scope=self,
           id='MLFLOW',
           service_name=service_name,
           cluster=cluster,
           task_definition=task_definition
        )

        fargate_service.node.add_dependency(listener)
        fargate_service.attach_to_application_target_group(target_group)
        fargate_service.connections.allow_from(lb, ec2.Port.tcp(5000), "allow from LB")
        database.connections.allow_default_port_from(fargate_service, "allow from MLFlow Container")

        # Setup autoscaling policy
        scaling = fargate_service.auto_scale_task_count(max_capacity=2)
        scaling.scale_on_cpu_utilization(
            id='AUTOSCALING',
            target_utilization_percent=70,
            scale_in_cooldown=core.Duration.seconds(60),
            scale_out_cooldown=core.Duration.seconds(60)
        )


app = core.App()
DeploymentStack(app, "DeploymentStack")
app.synth()
