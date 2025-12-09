# BeeCD

GitOps deployment with approval gates for Kubernetes. Review and approve what deploys before it goes live.

## What It Does

- **Approval gates** before any release reaches production
- **Manifest diffs** so you see exactly what will change
- **Multi-cluster control** from a single dashboard
- **Git-driven workflows** (push manifests, approve, done)
- **Release history** so you know what changed and who approved it

## What You Need

- Kubernetes 1.27+
- Helm 3.0+
- `kubectl` configured for your cluster
- A GitHub Personal Access Token with `repo` scope
- BeeCD images available in a registry your cluster can pull from

## Getting Started

### Install

#### 1. Create secrets

```bash
kubectl create namespace beecd

kubectl create secret generic hive-jwt \
  --namespace beecd \
  --from-literal=JWT_SECRET_KEY="$(openssl rand -base64 48)"

kubectl create secret generic github-tokens \
  --namespace beecd \
  --from-literal=GHUSER="your-github-username" \
  --from-literal=GHPASS="ghp_your_token_here"

./hack/generate-sops-gpg-secret.sh --namespace beecd --apply
```

#### 2. Install with Helm

```bash
helm dependency update deploy/helm/beecd

helm upgrade --install beecd deploy/helm/beecd \
  --namespace beecd \
  --set postgresql.enabled=true \
  --set minio.enabled=true \
  --set hiveServer.jwt.existingSecret=hive-jwt \
  --set hiveServer.github.existingSecret=github-tokens \
  --set hiveServer.sops.existingSecret=sops-gpg \
  --set hiveHq.jwt.secret="$(openssl rand -base64 48)"
```

> **Image registry:** The chart defaults to `registry:5000`. If your images are elsewhere, add:
> ```
> --set image.registry="your-registry.example.com" \
> --set image.tag="latest"
> ```

Wait for pods:
```bash
kubectl get pods -n beecd -w
```

You should see (all `1/1 Running`):
- `beecd-hive-server-*`
- `beecd-hive-hq-*`
- `beecd-postgresql-0`
- `beecd-minio-*`

#### 3. Access the UI

```bash
kubectl port-forward svc/beecd-hive-hq 8080:80 -n beecd
```

Open [http://localhost:8080](http://localhost:8080) in your browser. You should see the Hive HQ login page.

#### 4. Create Your Admin User

On first access, you need to create the initial admin user:

1. Click **Register** on the login page
2. Enter a username and password
3. Click **Create Account**

**Important:** Save your password somewhere secure. There is no password recovery mechanism. The first user created becomes the administrator.

### First Deployment

#### Step 1: Connect a cluster (install the agent)

BeeCD does **not** create Kubernetes clusters. A "cluster" in Hive HQ is an **existing** Kubernetes cluster that you connect by installing the BeeCD **agent** into it.

1. In Hive HQ, go to **Clusters** > **Add Cluster**
2. Give it a name and click **Create**
3. Hive HQ will generate an **agent manifest** - copy it
4. Save the manifest to a file (e.g., `agent.yaml`)
5. Apply it to the Kubernetes cluster you want BeeCD to deploy into:

```bash
kubectl apply -f agent.yaml
```

This can be the same cluster where you installed BeeCD, or a different one.

**About the generated manifest:**

The agent manifest includes pre-filled defaults for connecting back to the Hive server:

- **Hive gRPC Address**: Defaults to `beecd-hive-server.beecd.svc.cluster.local:5180` (in-cluster FQDN, plaintext). If the agent runs in a different cluster, you need to expose the Hive server via Ingress or LoadBalancer and update the address accordingly.
- **Agent Image**: Defaults to the same registry and tag configured in the Helm chart (e.g., `registry:5000/hive-agent:latest`).

You can override these defaults in `values.yaml`:

```yaml
hiveHq:
  env:
    hiveDefaultGrpcServer: "hive.example.com:443"
    agentDefaultImage: "ghcr.io/yourorg/hive-agent:v1.0.0"
```

Once the agent connects, you will see a recent heartbeat for the cluster under **Clusters**.

#### Step 2: Add a repository

1. In Hive HQ, go to **Repositories** > **Add Repository**
2. Paste the GitHub repository URL (e.g., `https://github.com/galleybytes/manifests`)
3. Click **Save**

#### Step 3: Add a branch and service

A **branch** tells BeeCD which git branch to watch. A **service** defines what manifests to deploy from that branch.

1. Click on the repository you just added

2. Click **Add Branch** and name the branch to track (e.g., `main`)

3. Click **Add Service** to define a deployable unit

   1. Fill in the service details:

      1. **Name**: A lowercase identifier for the service (e.g., `my-app`)
      2. **Manifest Path Template**: Where to find manifests in the repo. Use placeholders `{cluster}`, `{namespace}`, and `{service}` to organize by deployment target.

      Examples:
      1. `k8s/{cluster}/{namespace}/{service}/` - Separate directories per cluster/namespace/service
      2. `{cluster}/{namespace}/{service}.yaml` - Single file per service, organized by namespace

4. Click **Save**

#### Step 4: Create a cluster group and add your cluster to it

A **Cluster Group** is how you connect services to clusters. Services are assigned to cluster groups, and clusters in that group can deploy those services.

1. Go to **Cluster Groups** > **Add Group**
2. Give it a name (e.g., `production`) and click **Create**
3. Click on the group you just created
4. Click **Add Clusters** and select your cluster
5. Click **Add Services** and select the service you created in Step 3

#### Step 5: Label a namespace for deployment

In the Kubernetes cluster you connected in Step 1, label a namespace so BeeCD knows it is allowed to manage it:

```bash
kubectl create namespace my-app
kubectl label namespace my-app beecd/register=true
```

Within 60 seconds, the namespace will appear in Hive HQ under **Clusters** > your cluster.

#### Step 6: Register the service to the namespace

1. In Hive HQ, go to **Clusters** > your cluster
2. Find the `my-app` namespace
3. Click on the namespace to edit it
4. Select the service you want to deploy (only services from cluster groups this cluster belongs to will appear)
5. Click **Save**

#### Step 7: Point the release at a commit

Each release needs to know which git commit to deploy. This is called a **version**. You can create one manually:

1. Navigate to **Clusters** > select your cluster > scroll down to the **Releases** section
2. Find your release in the list and click on it to open the detail page
3. Click **Versions** > **Add Manual Version**
4. Enter a version tag (e.g., `v1.0.0`) and the git commit SHA from your repo
5. Click **Create Version**

BeeCD will pull the manifests from that commit and prepare them for deployment.

> **Tip:** For production, you can set up GitHub webhooks to create versions automatically when you push changes. See the Helm chart documentation for webhook configuration.

#### Step 8: Review and approve

1. Go to **Releases**
2. Click on the pending release
3. Review the **Diff** (shows what will be applied)
4. Click **Approve**

The manifests will deploy to your cluster. You can verify:

```bash
kubectl get all -n my-app
```

