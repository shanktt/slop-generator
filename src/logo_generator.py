import argparse
import base64
import os

from dotenv import load_dotenv
from openai import OpenAI
from rich.progress import Progress, SpinnerColumn, TextColumn

load_dotenv()


class LogoGenerator:
    def __init__(self, color: str):
        self.client = OpenAI()
        self.system_prompt = f"""
        You are a logo generator. You will be given a prompt and you will need to generate a logo for a B2B SaaS business.
        The logo should be a vector image and should be in the style of a modern, minimalistic logo.
        The logo should be in some shade of {color}
        Do not include any text in the logo.
        """

    def generate_logo(self, prompt, num_logos):
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            _ = progress.add_task(
                f"Generating {num_logos} logo{'s' if num_logos > 1 else ''}...",
                total=None,
            )
            img = self.client.images.generate(
                model="gpt-image-1",
                prompt=f"{self.system_prompt}\n\n{prompt}",
                n=num_logos,
                size="1024x1024",
                background="transparent",
            )

        os.makedirs("outputs", exist_ok=True)

        for i in range(num_logos):
            image_bytes = base64.b64decode(img.data[i].b64_json)

            with open(f"outputs/output_{i}.png", "wb") as f:
                f.write(image_bytes)
            print(f"Logo generated and saved to outputs/output_{i}.png")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("prompt", type=str)
    parser.add_argument("--color", type=str, default="purple")
    parser.add_argument("--num", type=int, default=1)

    args = parser.parse_args()
    logo_generator = LogoGenerator(args.color)
    logo_generator.generate_logo(args.prompt, args.num)
